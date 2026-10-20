#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
terraform_bin="${TERRAFORM_BIN:-$repo_root/build/tool-cache/terraform/terraform}"
aws_bin="${AWS_BIN:-aws}"
if [[ ! -x "$terraform_bin" ]]; then
  echo "Terraform binary is not executable: $terraform_bin" >&2
  exit 2
fi
if ! command -v "$aws_bin" >/dev/null 2>&1; then
  echo "AWS CLI is required to verify retained queue and ECS task state." >&2
  exit 2
fi

phase="${1:-post-teardown}"
if [[ "$phase" != "preflight" && "$phase" != "drained" && "$phase" != "post-teardown" ]]; then
  echo "Usage: $0 [preflight|drained|post-teardown]" >&2
  exit 2
fi

state_list="$("$terraform_bin" -chdir="$repo_root/infra" state list)"
inventory_json="$("$terraform_bin" -chdir="$repo_root/infra" output -json session_teardown_inventory)"
required_addresses="$(python3 -c 'import json,sys; print("\n".join(json.loads(sys.argv[1])["required_addresses"]))' "$inventory_json")"
queue_urls_json="$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["queue_urls"]))' "$inventory_json")"
ecs_cluster="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["ecs_cluster_name"])' "$inventory_json")"
task_family="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["archive_task_family"])' "$inventory_json")"
schedule_name="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["archive_schedule_name"])' "$inventory_json")"
schedule_required="$(python3 -c 'import json,sys; print(str(json.loads(sys.argv[1])["archive_schedule_required"]).lower())' "$inventory_json")"
task_wait_seconds="${TEARDOWN_TASK_WAIT_SECONDS:-600}"
task_poll_seconds="${TEARDOWN_TASK_POLL_SECONDS:-5}"

session_resources="$(printf '%s\n' "$state_list" | grep -E '^(aws_vpc_endpoint\.interface\[|aws_vpc_endpoint\.(s3|dynamodb)\[|aws_security_group\.(alb|tasks|endpoints)\[|aws_lb(_target_group|_listener|_listener_rule)?\.|data\.aws_secretsmanager_secret_version\.oidc_client\[|aws_ecs_task_definition\.(service|audit_consumer)\[|aws_iam_role_policy\.application\[|aws_ecs_service\.service\[|aws_appautoscaling_(target|policy)\.|aws_iam_role(_policy)?\.audit_scheduler\[|aws_scheduler_schedule\.audit_archive\[)' || true)"
foundation_missing=""
while IFS= read -r required; do
  [[ -z "$required" ]] && continue
  if ! grep -Fqx "$required" <<<"$state_list"; then
    foundation_missing+="  $required\n"
  fi
done <<<"$required_addresses"

if [[ "$phase" == "preflight" ]]; then
  if [[ "$schedule_required" == "true" ]]; then
    schedule_state="$("$aws_bin" scheduler get-schedule --name "$schedule_name" --group-name default --query State --output text)"
    if [[ "$schedule_state" != "DISABLED" ]]; then
      echo "Archive schedule must be DISABLED before removing networking (current state: $schedule_state)." >&2
      exit 1
    fi
  fi
  if [[ -n "$session_resources" ]]; then
    echo "Session resources remain in Terraform state; preflight is expected before teardown." >&2
  fi
fi

wait_for_archive_tasks_and_enis() {
  local started now running stopped tasks task_json task_state eni_ids eni eni_result remaining
  started="$(date +%s)"
  while true; do
    running="$("$aws_bin" ecs list-tasks --cluster "$ecs_cluster" --family "$task_family" --desired-status RUNNING --query taskArns --output json)"
    stopped="$("$aws_bin" ecs list-tasks --cluster "$ecs_cluster" --family "$task_family" --desired-status STOPPED --query taskArns --output json)"
    tasks="$(python3 -c 'import json,sys; print("\n".join(sorted(set(json.loads(sys.argv[1]) + json.loads(sys.argv[2])))))' "$running" "$stopped")"
    remaining=""
    if [[ -n "$tasks" ]]; then
      while IFS= read -r task; do
        [[ -z "$task" ]] && continue
        task_json="$("$aws_bin" ecs describe-tasks --cluster "$ecs_cluster" --tasks "$task" --output json)"
        task_state="$(python3 -c 'import json,sys; task=json.loads(sys.argv[1])["tasks"][0]; print(task.get("lastStatus", "UNKNOWN"))' "$task_json")"
        if [[ "$task_state" != "STOPPED" ]]; then
          remaining+="  $task (lastStatus=$task_state)\n"
          continue
        fi
        eni_ids="$(python3 -c 'import json,sys; task=json.loads(sys.argv[1])["tasks"][0]; print("\n".join(detail["value"] for attachment in task.get("attachments", []) for detail in attachment.get("details", []) if detail.get("name") == "networkInterfaceId"))' "$task_json")"
        while IFS= read -r eni; do
          [[ -z "$eni" ]] && continue
          if eni_result="$("$aws_bin" ec2 describe-network-interfaces --network-interface-ids "$eni" --query 'NetworkInterfaces[].NetworkInterfaceId' --output text 2>&1)"; then
            if [[ -n "$eni_result" && "$eni_result" != "None" ]]; then
              remaining+="  $task ENI $eni still exists\n"
            fi
          elif [[ "$eni_result" != *InvalidNetworkInterfaceID.NotFound* ]]; then
            echo "Could not verify archive task ENI $eni: $eni_result" >&2
            return 2
          fi
        done <<<"$eni_ids"
      done <<<"$tasks"
    fi
    if [[ -z "$remaining" ]]; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - started >= task_wait_seconds )); then
      echo "Archive tasks must reach STOPPED and their task ENIs must be deleted before networking teardown:" >&2
      printf '%b' "$remaining" >&2
      return 1
    fi
    sleep "$task_poll_seconds"
  done
}

wait_for_archive_tasks_and_enis

queue_nonempty=""
if [[ "$phase" != "preflight" ]]; then
  while IFS=$'\t' read -r queue_name queue_url; do
    [[ -z "$queue_name" ]] && continue
    attributes="$("$aws_bin" sqs get-queue-attributes --queue-url "$queue_url" --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible ApproximateNumberOfMessagesDelayed --query 'Attributes.[ApproximateNumberOfMessages,ApproximateNumberOfMessagesNotVisible,ApproximateNumberOfMessagesDelayed]' --output text)"
    numbers="$(tr '\t' ' ' <<<"$attributes")"
    if [[ -z "$numbers" || "$numbers" =~ [^0-9\ ] ]]; then
      echo "Could not read numeric SQS depth for $queue_name: $attributes" >&2
      exit 2
    fi
    if [[ "$numbers" != "0 0 0" ]]; then
      queue_nonempty+="  $queue_name: $numbers\n"
    fi
  done < <(python3 -c 'import json,sys; print("".join(f"{k}\t{v}\n" for k,v in json.loads(sys.argv[1]).items()))' "$queue_urls_json")
fi

if [[ -n "$queue_nonempty" ]]; then
  echo "Retained audit/feedback queues and DLQs must be drained to S3 before teardown:" >&2
  printf '%b' "$queue_nonempty" >&2
  exit 1
fi

if [[ "$phase" == "post-teardown" ]]; then
  if [[ -n "$session_resources" ]]; then
    echo "Session resources remain in Terraform state; review these before calling teardown complete:" >&2
    printf '%s\n' "$session_resources" >&2
  fi
  if [[ -n "$foundation_missing" ]]; then
    echo "Required deployment-derived foundation resources are missing from Terraform state:" >&2
    printf '%b' "$foundation_missing" >&2
  fi
  if [[ -n "$session_resources" || -n "$foundation_missing" ]]; then
    exit 1
  fi
fi

if [[ "$phase" == "preflight" ]]; then
  echo "Archive schedule is disabled; archive tasks are STOPPED and their ENIs are deleted."
elif [[ "$phase" == "drained" ]]; then
  echo "Archive schedule is disabled, archive task ENIs are deleted, and all retained queues are empty."
else
  echo "Archive task ENIs are deleted, all retained queues are empty, and deployment-derived foundation resources remain."
fi
echo "Verify external lab hooks and the shared alarm topic using the runbook checklist."
