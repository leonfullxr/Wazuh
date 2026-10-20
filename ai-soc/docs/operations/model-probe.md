# Bedrock capability probe

This probe produces **capability evidence only**. It does not satisfy or change
any LV gate; every live gate remains `NOT_RUN`. Use synthetic text only.

## Prepare

1. Complete account funding and confirm the selected model's billing eligibility
   and any cash cap. Complete the model's activation requirements with the
   separate activation principal. AWS documents Marketplace permissions and the
   Anthropic first-time use form as model access prerequisites.
2. Publish a numbered guardrail version and decide on a short synthetic prompt
   that this version blocks. The probe requires this prompt explicitly; it does
   not guess policy content or treat a non-block as success.
3. Configure minimal synthetic invocation logging **before the first
   Converse**. Bedrock invocation logging applies to all supported invocations
   in that account and Region and records request and response content. Use a
   dedicated Region/window with no other invocations, enable text only, and use
   an encrypted, access-restricted destination with a short retention period.
   `CountTokens` is not among the operations listed for invocation logging.
4. Assume the probe role as the operator and use its temporary credentials.
   Resolve the selected inference profile with `GetInferenceProfile` in the
   source Region and collect every destination `models[].modelArn`. Choose the
   exact regional foundation-model ARN supported by native `CountTokens` as the
   counter model. Attach `config/qualification/probe-role-policy.json`, replace
   the profile ARN, guardrail ARN/version, and destination ARN placeholders,
   and add one entry for each profile destination to every destination resource
   list, including the explicit-deny lists. The policy denies missing or
   mismatched guardrail identifiers and denies model calls outside the
   profile/destination allowlist, matching the runtime policy boundaries. The
   counter ARN must have an empty account segment, as in
   `arn:aws:bedrock:eu-central-1::foundation-model/example`. The invocation
   resource list grants the exact profile plus its routed foundation models;
   `CountTokens` is scoped to only those destination foundation models. The
   policy also allows `bedrock:ApplyGuardrail` on the one selected guardrail.
   Do not attach
   `config/qualification/activation-principal-policy.json` to this role.
   Attach that separate policy only to the human activation principal, and
   replace its product ID from the selected Marketplace listing. Apply a trust
   policy that permits assumption only by the designated operator identity and
   requires MFA where the operator setup supports it.

## Run

With the probe role already assumed, run exactly one sequence: one native
`bedrock-runtime` `CountTokens` against the separate destination foundation
model ARN, one guarded `Converse` against the inference profile with the built-in tiny
benign synthetic prompt, then one guarded `Converse` with the explicit
guardrail-matching block prompt. Both Converse calls are bounded to at most 32
and 1 output tokens respectively. The blocked prompt is limited to 512 characters. The SDK uses a 3-second
connection timeout, 15-second read timeout, one total attempt, and one connection. The script also
calls STS `GetCallerIdentity` to bind the evidence to an account and principal.

```sh
uv run --locked --offline python scripts/qualification/model_probe.py \
  --region eu-central-1 \
  --model-arn arn:aws:bedrock:eu-central-1:123456789012:inference-profile/example \
  --count-model-arn arn:aws:bedrock:eu-central-1::foundation-model/example \
  --guardrail-arn arn:aws:bedrock:eu-central-1:123456789012:guardrail/example \
  --guardrail-version 1 \
  --blocked-prompt 'synthetic phrase matched by the published guardrail policy' \
  --evidence build/evidence/model-probe-2026-10-07.json
```

The artifact records UTC timestamps, account, caller ARN, Region, model,
guardrail ARN/version, API request IDs, counted input tokens, Converse stop
reasons and returned usage. It records no prompt or model output. A successful
benign response must have an `end_turn` or `stop_sequence` completion reason and
non-empty text output. The block must independently return
`guardrail_intervened` with input, output, and total token usage all zero;
otherwise the artifact is `failed` and the command exits 1.
Preserve the artifact with the qualification evidence and keep every LV result
`NOT_RUN`.

## Revoke

After the calls and evidence review, revoke the probe role's model permissions
or delete the temporary role, then end the assumed session. Disable the
temporary invocation logging configuration after confirming delivery, while
retaining only the synthetic log and evidence for the approved retention
period. Do not remove the account's persistent qualification logging setup if
it is separately required by the qualification foundation.

## References

- [CountTokens API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_CountTokens.html)
- [Converse API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html)
- [Guardrails with the Converse API](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-converse-api.html)
- [Guardrail IAM permissions and identifiers](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html)
- [Bedrock model invocation logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)
- [Request access to Bedrock models](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html)
- [Inference profile destinations](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-view.html)
