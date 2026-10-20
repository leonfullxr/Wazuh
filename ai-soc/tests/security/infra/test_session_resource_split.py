from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from terraform_root import TERRAFORM, prepare_root_module

REPO_ROOT = Path(__file__).resolve().parents[3]
TFVARS = Path(__file__).parent / "data/root_variables_validation/valid.tfvars.json"
SESSION_PREFIXES = (
    "aws_vpc_endpoint.interface[",
    "aws_vpc_endpoint.s3[",
    "aws_vpc_endpoint.dynamodb[",
    "aws_security_group.alb[",
    "aws_security_group.tasks[",
    "aws_security_group.endpoints[",
    "aws_lb.",
    "aws_lb_target_group.",
    "aws_lb_listener.",
    "aws_lb_listener_rule.",
    "data.aws_secretsmanager_secret_version.oidc_client[",
    "aws_ecs_task_definition.service[",
    "aws_iam_role_policy.application[",
    "aws_ecs_service.service[",
    "aws_appautoscaling_target.service[",
    "aws_appautoscaling_policy.cpu[",
    "aws_ecs_task_definition.audit_consumer[",
    "aws_iam_role.audit_scheduler[",
    "aws_iam_role_policy.audit_scheduler[",
    "aws_scheduler_schedule.audit_archive[",
)


@pytest.fixture(scope="module")
def foundation_plan(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    if not TERRAFORM.is_file():
        pytest.skip("pinned terraform binary is not bootstrapped")
    module = prepare_root_module(tmp_path_factory.mktemp("session-split") / "root")
    plan_file = module / "foundation.tfplan"
    missing_email = subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-var-file={TFVARS}",
            "-var=enable_session_resources=false",
        ],
        cwd=module,
        capture_output=True,
        text=True,
        env={**os.environ, "AWS_EC2_METADATA_DISABLED": "true"},
    )
    assert missing_email.returncode != 0
    assert "Set account_cost_budget_alert_email" in missing_email.stderr + missing_email.stdout
    planned = subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-var-file={TFVARS}",
            "-var=enable_session_resources=false",
            "-var=enable_account_cost_budgets=true",
            "-var=account_cost_budget_alert_email=ops@example.test",
            f"-out={plan_file}",
        ],
        cwd=module,
        capture_output=True,
        text=True,
        env={**os.environ, "AWS_EC2_METADATA_DISABLED": "true"},
    )
    assert planned.returncode == 0, planned.stderr + planned.stdout
    shown = subprocess.run(
        [str(TERRAFORM), "show", "-json", str(plan_file)],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(shown.stdout)


def test_real_root_disables_hourly_resources_and_keeps_foundation(
    foundation_plan: dict[str, object],
) -> None:
    changes = foundation_plan["resource_changes"]
    assert isinstance(changes, list)
    addresses = [change["address"] for change in changes]
    by_address = {change["address"]: change for change in changes}
    assert not any(address.startswith(SESSION_PREFIXES) for address in addresses)
    for retained in (
        "aws_kms_key.storage",
        'aws_dynamodb_table.state["state"]',
        "aws_s3_bucket.audit_archive",
        "aws_s3_bucket.invocation_logs",
        "aws_sqs_queue.audit",
        "aws_cloudwatch_log_group.service",
        "aws_budgets_budget.account_gross_cost[0]",
        "aws_budgets_budget.account_cash_cost[0]",
    ):
        assert retained in addresses
    gross = by_address["aws_budgets_budget.account_gross_cost[0]"]["change"]["after"]
    cash = by_address["aws_budgets_budget.account_cash_cost[0]"]["change"]["after"]
    assert gross["budget_type"] == cash["budget_type"] == "COST"
    assert gross["cost_types"][0]["include_credit"] is False
    assert gross["cost_types"][0]["include_refund"] is False
    assert cash["cost_types"][0]["include_credit"] is True
    assert cash["cost_types"][0]["include_refund"] is True
    assert gross.get("filter") in (None, []) and cash.get("filter") in (None, [])


def test_existing_full_root_state_addresses_have_move_rules() -> None:
    moved = (REPO_ROOT / "infra/moved.tf").read_text(encoding="utf-8")
    for address in (
        "aws_lb.service",
        "aws_security_group.tasks",
        "aws_vpc_endpoint.s3",
        "aws_ecs_service.service",
        "aws_scheduler_schedule.audit_archive",
    ):
        assert f"from = {address}\n" in moved
        assert f"to   = {address}[0]" in moved


def test_real_root_allows_budget_alternative_but_gates_deny_action(tmp_path: Path) -> None:
    if not TERRAFORM.is_file():
        pytest.skip("pinned terraform binary is not bootstrapped")
    module = prepare_root_module(tmp_path / "budget-root")
    env = {**os.environ, "AWS_EC2_METADATA_DISABLED": "true"}
    alternative = subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-var-file={TFVARS}",
            "-var=enable_session_resources=false",
            "-var=enable_account_cost_budgets=false",
        ],
        cwd=module,
        capture_output=True,
        text=True,
        env=env,
    )
    assert alternative.returncode == 0, alternative.stderr + alternative.stdout
    denied = subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-var-file={TFVARS}",
            "-var=enable_session_resources=false",
            "-var=enable_account_cost_budgets=false",
            "-var=enable_bedrock_spend_budget=true",
        ],
        cwd=module,
        capture_output=True,
        text=True,
        env=env,
    )
    assert denied.returncode != 0
    enabled = subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-var-file={TFVARS}",
            "-var=enable_session_resources=false",
            "-var=enable_account_cost_budgets=true",
            "-var=account_cost_budget_alert_email=ops@example.test",
            "-var=enable_bedrock_spend_budget=true",
        ],
        cwd=module,
        capture_output=True,
        text=True,
        env=env,
    )
    assert enabled.returncode == 0, enabled.stderr + enabled.stdout


def test_real_root_inventory_uses_each_configured_site_and_optional_features(
    tmp_path: Path,
) -> None:
    if not TERRAFORM.is_file():
        pytest.skip("pinned terraform binary is not bootstrapped")
    module = prepare_root_module(tmp_path / "inventory-root")
    variables = json.loads(TFVARS.read_text(encoding="utf-8"))
    variables["sites"]["prod"] = {
        **variables["sites"]["lab"],
        "jwt_audience": "soc-prod",
        "ca_secret_arn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod-ca",
    }
    variables["enable_account_cost_budgets"] = False
    variables["enable_bedrock_model_invocation_logging"] = True
    variables["enable_cloudtrail"] = True
    variables_file = tmp_path / "multi-site.tfvars.json"
    variables_file.write_text(json.dumps(variables), encoding="utf-8")
    plan_file = module / "inventory.tfplan"
    planned = subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-var-file={variables_file}",
            "-var=enable_session_resources=false",
            f"-out={plan_file}",
        ],
        cwd=module,
        capture_output=True,
        text=True,
        env={**os.environ, "AWS_EC2_METADATA_DISABLED": "true"},
    )
    assert planned.returncode == 0, planned.stderr + planned.stdout
    shown = subprocess.run(
        [str(TERRAFORM), "show", "-json", str(plan_file)],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    addresses = json.loads(shown.stdout)["planned_values"]["outputs"][
        "foundation_inventory_addresses"
    ]["value"]
    assert 'aws_kms_key.site_signing["lab"]' in addresses
    assert 'aws_kms_key.site_signing["prod"]' in addresses
    assert "aws_budgets_budget.account_gross_cost[0]" not in addresses
    assert "aws_bedrock_model_invocation_logging_configuration.service[0]" in addresses
    assert "aws_cloudtrail.service[0]" in addresses


def test_real_root_endpoint_and_consumer_policies_allow_feedback_archiving(
    tmp_path: Path,
) -> None:
    if not TERRAFORM.is_file():
        pytest.skip("pinned terraform binary is not bootstrapped")
    module = prepare_root_module(tmp_path / "feedback-policy-root")
    plan_file = module / "feedback-policy.tfplan"
    planned = subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-var-file={TFVARS}",
            "-var=enable_session_resources=true",
            "-var=enable_account_cost_budgets=false",
            '-target=aws_vpc_endpoint.interface["sqs"]',
            "-target=aws_iam_role_policy.audit_consumer",
            f"-out={plan_file}",
        ],
        cwd=module,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_SESSION_TOKEN": "",
            "AWS_PROFILE": "",
            "AWS_EC2_METADATA_DISABLED": "true",
        },
    )
    assert planned.returncode == 0, planned.stderr + planned.stdout
    shown = subprocess.run(
        [str(TERRAFORM), "show", "-json", str(plan_file)],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    changes = json.loads(shown.stdout)["resource_changes"]
    resources = json.loads(shown.stdout)["configuration"]["root_module"]["resources"]
    config_by_address = {resource["address"]: resource for resource in resources}
    assert 'aws_vpc_endpoint.interface["sqs"]' in {change["address"] for change in changes}
    assert "aws_sqs_queue.feedback" in {change["address"] for change in changes}
    assert (
        "aws_sqs_queue.feedback.arn"
        in config_by_address["aws_iam_role_policy.audit_consumer"]["expressions"]["policy"][
            "references"
        ]
    )
    endpoint_policy_refs = config_by_address["aws_vpc_endpoint.interface"]["expressions"]["policy"][
        "references"
    ]
    assert "local.interface_policy_statements" in endpoint_policy_refs
    main = (REPO_ROOT / "infra/main.tf").read_text(encoding="utf-8")
    sqs_endpoint_policy = main.split('"sqs" = [', 1)[1].split('"bedrock-runtime"', 1)[0]
    assert (
        '{ Effect = "Allow", Principal = "*", '
        'Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", '
        '"sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], '
        "Resource = [aws_sqs_queue.audit.arn, aws_sqs_queue.feedback.arn] }"
    ) in sqs_endpoint_policy


def test_real_root_requires_proxy_and_exact_host_coverage_for_qualification(
    tmp_path: Path,
) -> None:
    if not TERRAFORM.is_file():
        pytest.skip("pinned terraform binary is not bootstrapped")
    module = prepare_root_module(tmp_path / "qualification-egress-root")
    base = [
        str(TERRAFORM),
        "plan",
        "-input=false",
        "-refresh=false",
        f"-var-file={TFVARS}",
        "-var=enable_session_resources=false",
        "-var=qualification_profile=true",
        "-var=idp_in_vpc=true",
        "-var=account_cost_budget_alert_email=ops@example.test",
    ]
    env = {**os.environ, "AWS_EC2_METADATA_DISABLED": "true"}
    direct = subprocess.run(
        [*base, "-var=alb_public_key_egress_mode=nat"],
        cwd=module,
        capture_output=True,
        text=True,
        env=env,
    )
    assert direct.returncode != 0
    assert "qualification requires a TLS-protected hostname-allowlisting proxy" in (
        direct.stderr + direct.stdout
    )

    proxy = [
        *base,
        "-var=alb_public_key_egress_mode=proxy",
        '-var=alb_public_key_egress_cidrs=["10.0.1.4/32"]',
        "-var=alb_public_key_https_proxy=https://proxy.example.test:443",
    ]
    missing_hosts = subprocess.run(proxy, cwd=module, capture_output=True, text=True, env=env)
    assert missing_hosts.returncode != 0
    assert "exact allowlisted ALB key" in missing_hosts.stderr + missing_hosts.stdout

    configured_hosts = subprocess.run(
        [
            *proxy,
            '-var=qualification_proxy_allowed_hosts=["public-keys.auth.elb.us-east-1.amazonaws.com","idp.example.test"]',
        ],
        cwd=module,
        capture_output=True,
        text=True,
        env=env,
    )
    assert configured_hosts.returncode == 0, configured_hosts.stderr + configured_hosts.stdout


def _inventory_fixture() -> dict[str, object]:
    return {
        "required_addresses": [
            "aws_kms_key.storage",
            "aws_kms_alias.storage",
            "aws_kms_key_policy.storage",
            'aws_kms_key.site_signing["lab"]',
            'aws_kms_alias.site_signing["lab"]',
            'aws_dynamodb_table.state["state"]',
            "aws_s3_bucket.audit_archive",
            "aws_s3_bucket.invocation_logs",
            "aws_s3_bucket.docs",
            "aws_sqs_queue.audit",
            "aws_sqs_queue.audit_dlq",
            "aws_sqs_queue.feedback",
            "aws_sqs_queue.feedback_dlq",
            "aws_cloudwatch_log_group.service",
            "aws_cloudwatch_metric_alarm.audit_queue_age",
            "aws_cloudwatch_metric_alarm.audit_dlq",
            "aws_cloudwatch_metric_alarm.recovery_lag",
            "aws_cloudwatch_metric_alarm.recovery_backlog",
            "aws_cloudwatch_metric_alarm.admission_rejections",
        ],
        "queue_urls": {
            "audit": "https://sqs.example.test/audit",
            "audit_dlq": "https://sqs.example.test/audit-dlq",
            "feedback": "https://sqs.example.test/feedback",
            "feedback_dlq": "https://sqs.example.test/feedback-dlq",
        },
        "ecs_cluster_name": "test-cluster",
        "archive_task_family": "test-archive",
        "archive_schedule_name": "test-schedule",
        "archive_schedule_required": True,
        "account_budgets_configured": False,
    }


def _inventory_state() -> str:
    return "\n".join(_inventory_fixture()["required_addresses"])


def _run_inventory_check(
    tmp_path: Path,
    *,
    state: str,
    depths: str = "0 0 0",
    tasks: str = "None",
    stopped_tasks: str = "None",
    task_status: str = "RUNNING",
    task_eni: str = "",
    eni_state: str = "None",
    schedule: str = "DISABLED",
    phase: str = "post-teardown",
    task_wait_seconds: int = 0,
    transitions: bool = False,
) -> subprocess.CompletedProcess[str]:
    state_path = tmp_path / "state.txt"
    state_path.write_text(state, encoding="utf-8")
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(_inventory_fixture()), encoding="utf-8")
    terraform = tmp_path / "terraform"
    terraform.write_text(
        "\n".join(
            (
                "#!/usr/bin/env bash",
                'if [[ "$*" == *"state list"* ]]; then',
                '  cat "$STATE_FIXTURE"',
                "else",
                '  cat "$INVENTORY_FIXTURE"',
                "fi",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    terraform.chmod(0o755)
    aws = tmp_path / "aws"
    aws.write_text(
        "\n".join(
            (
                "#!/usr/bin/env bash",
                'case "$1" in',
                '  scheduler) echo "$SCHEDULE_STATE" ;;',
                "  ecs)",
                '    case "$2" in',
                "      list-tasks)",
                '        if [[ "$*" == *"desired-status RUNNING"* ]]; then',
                '          printf "%s\\n" "$RUNNING_TASKS"',
                "        else",
                '          printf "%s\\n" "$STOPPED_TASKS"',
                "        fi ;;",
                "      describe-tasks)",
                '        if [[ "$TRANSITIONS" != true ]]; then',
                '          printf "%s\\n" "$TASK_DESCRIPTION"',
                "        else",
                '          count=$(cat "$DESCRIBE_COUNT" 2>/dev/null || echo 0)',
                "          count=$((count + 1))",
                '          echo "$count" > "$DESCRIBE_COUNT"',
                "          if (( count == 1 )); then",
                '            printf "%s\\n" "$TASK_STOPPING_JSON"',
                "          else",
                '            printf "%s\\n" "$TASK_STOPPED_JSON"',
                "          fi",
                "        fi ;;",
                "    esac ;;",
                "  ec2)",
                '    if [[ "$TRANSITIONS" != true ]]; then',
                '      echo "$ENI_STATE"',
                "    else",
                '      count=$(cat "$ENI_COUNT" 2>/dev/null || echo 0)',
                "      count=$((count + 1))",
                '      echo "$count" > "$ENI_COUNT"',
                '      if (( count == 1 )); then echo "eni-test"; else echo "None"; fi',
                "    fi ;;",
                '  sqs) echo "$QUEUE_DEPTHS" ;;',
                "esac",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    aws.chmod(0o755)
    return subprocess.run(
        [str(REPO_ROOT / "scripts/infra/check-session-teardown.sh"), phase],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "TERRAFORM_BIN": str(terraform),
            "AWS_BIN": str(aws),
            "STATE_FIXTURE": str(state_path),
            "INVENTORY_FIXTURE": str(inventory_path),
            "QUEUE_DEPTHS": depths,
            "RUNNING_TASKS": json.dumps([] if tasks == "None" else [tasks]),
            "STOPPED_TASKS": json.dumps([] if stopped_tasks == "None" else [stopped_tasks]),
            "TASK_DESCRIPTION": json.dumps(
                {
                    "tasks": [
                        {
                            "lastStatus": task_status,
                            "attachments": (
                                [
                                    {
                                        "details": [
                                            {
                                                "name": "networkInterfaceId",
                                                "value": task_eni,
                                            }
                                        ]
                                    }
                                ]
                                if task_eni
                                else []
                            ),
                        }
                    ]
                }
            ),
            "TASK_STOPPING_JSON": json.dumps(
                {"tasks": [{"lastStatus": "STOPPING", "attachments": []}]}
            ),
            "TASK_STOPPED_JSON": json.dumps(
                {
                    "tasks": [
                        {
                            "lastStatus": "STOPPED",
                            "attachments": [
                                {
                                    "details": [
                                        {
                                            "name": "networkInterfaceId",
                                            "value": "eni-test",
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ),
            "ENI_STATE": eni_state,
            "SCHEDULE_STATE": schedule,
            "TEARDOWN_TASK_WAIT_SECONDS": str(task_wait_seconds),
            "TEARDOWN_TASK_POLL_SECONDS": "0.01",
            "TRANSITIONS": str(transitions).lower(),
            "DESCRIBE_COUNT": str(tmp_path / "describe-count"),
            "ENI_COUNT": str(tmp_path / "eni-count"),
        },
    )


def test_session_teardown_inventory_script_accepts_multi_featureless_foundation(
    tmp_path: Path,
) -> None:
    result = _run_inventory_check(tmp_path, state=_inventory_state())
    assert result.returncode == 0, result.stderr + result.stdout
    assert "all retained queues are empty" in result.stdout


@pytest.mark.parametrize(
    ("state", "depths", "tasks", "expected_text"),
    [
        (
            _inventory_state() + '\naws_vpc_endpoint.interface["bedrock-runtime"]',
            "0 0 0",
            "None",
            "Session resources remain",
        ),
        (_inventory_state(), "1 0 0", "None", "must be drained to S3"),
        (
            _inventory_state(),
            "0 0 0",
            "arn:aws:ecs:task:running",
            "Archive tasks must reach STOPPED",
        ),
        (
            "aws_kms_key.storage",
            "0 0 0",
            "None",
            "deployment-derived foundation resources are missing",
        ),
    ],
)
def test_session_teardown_inventory_script_rejects_incomplete_state(
    tmp_path: Path, state: str, depths: str, tasks: str, expected_text: str
) -> None:
    result = _run_inventory_check(tmp_path, state=state, depths=depths, tasks=tasks)
    assert result.returncode == 1
    assert expected_text in result.stdout + result.stderr


def test_session_teardown_waits_for_stop_and_task_eni_deletion(tmp_path: Path) -> None:
    result = _run_inventory_check(
        tmp_path,
        state=_inventory_state(),
        tasks="arn:aws:ecs:task:archive",
        task_wait_seconds=30,
        transitions=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "task ENIs are deleted" in result.stdout
    assert (tmp_path / "describe-count").read_text(encoding="utf-8").strip() == "3"
    assert (tmp_path / "eni-count").read_text(encoding="utf-8").strip() == "2"


def test_session_teardown_rejects_stopped_tasks_with_live_enis(tmp_path: Path) -> None:
    result = _run_inventory_check(
        tmp_path,
        state=_inventory_state(),
        stopped_tasks="arn:aws:ecs:task:archive",
        task_status="STOPPED",
        task_eni="eni-test",
        eni_state="eni-test",
    )
    assert result.returncode == 1
    assert "ENI eni-test still exists" in result.stderr


def test_session_teardown_preflight_requires_disabled_schedule(
    tmp_path: Path,
) -> None:
    result = _run_inventory_check(
        tmp_path, state=_inventory_state(), schedule="ENABLED", phase="preflight"
    )
    assert result.returncode == 1
    assert "must be DISABLED" in result.stderr


def test_preflight_allows_pending_messages_but_drained_check_rejects_them(
    tmp_path: Path,
) -> None:
    preflight = _run_inventory_check(
        tmp_path, state=_inventory_state(), depths="3 0 0", phase="preflight"
    )
    assert preflight.returncode == 0, preflight.stderr + preflight.stdout
    drained = _run_inventory_check(
        tmp_path, state=_inventory_state(), depths="3 0 0", phase="drained"
    )
    assert drained.returncode == 1
    assert "must be drained to S3" in drained.stderr
