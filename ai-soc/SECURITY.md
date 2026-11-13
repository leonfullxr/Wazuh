# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub private vulnerability reporting on the leonfullxr/Wazuh repository. Open the [Security tab](https://github.com/leonfullxr/Wazuh/security) and choose "Report a vulnerability" if private reporting is enabled. If that option is unavailable, contact the repository owner privately to arrange a reporting channel before sharing details.

Do not open a public issue for a vulnerability. A public issue discloses the problem before a fix is available.

Reports are handled on a best-effort basis. There is no response time commitment, no bug bounty, and no guaranteed fix timeline.

## Supported versions

Only the latest commit on the main branch is supported. Older commits, tags, and forks do not receive security fixes.

## Security considerations for operators

This software processes security alerts and may send alert data to third-party LLM providers, depending on how it is configured. Operators are responsible for the following:

* Reviewing which data leaves their environment, and which providers receive it.
* Protecting credentials. Use a secrets manager, and never commit .env files or API keys.
* Restricting network exposure of the API and the web client. Do not expose either to untrusted networks without authentication and access controls.
* Validating every AI-generated verdict or recommendation before acting on it.

This software is not a replacement for human analysts. Do not rely on its output as the only basis for incident response decisions.

## Disclaimer

This software is provided "AS IS", without warranty of any kind, express or implied. The author and contributors accept no liability for any damages, data loss, missed detections, false positives, security incidents, costs (including LLM and cloud costs), or other consequences arising from its use. Use is at your own risk.

This project is not affiliated with or endorsed by Wazuh Inc. or any LLM provider.

The MIT License in [LICENSE](LICENSE) contains the full terms.
