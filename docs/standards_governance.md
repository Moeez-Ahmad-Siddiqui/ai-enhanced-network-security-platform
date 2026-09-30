# Standards, Governance, Failure Recovery and Scalability

## 1. NIST Cybersecurity Framework Mapping

### Identify
- Identify monitored network assets.
- Collect network telemetry using Zeek and Suricata.
- Establish behavioural baselines.

### Protect
- Apply least-privilege security policies.
- Generate dynamic quarantine decisions.
- Use network segmentation concepts.

### Detect
- Detect behavioural anomalies using Isolation Forest.
- Monitor network protocols and traffic.
- Correlate network observations with IOC data.
- Use Suricata signature-based detection.

### Respond
- Calculate combined security risk.
- Generate investigation and quarantine decisions.
- Collect forensic evidence.
- Generate incident response reports.

### Recover
- Investigate the incident.
- Restore normal access after verification.
- Update baselines and security policies.
- Review the incident for future improvement.

## 2. ISO/IEC 27001 Alignment

The prototype considers selected information-security control concepts such as:
- Access control
- Monitoring and logging
- Incident management
- Asset protection
- Security-event investigation

This project does not claim ISO/IEC 27001 certification or full organisational compliance.

## 3. Governance

Security decisions should follow a controlled process:

1. Detect suspicious behaviour.
2. Correlate multiple security signals.
3. Calculate risk.
4. Record the decision.
5. Apply the appropriate response.
6. Preserve evidence.
7. Investigate the event.
8. Restore access only after verification.
9. Record lessons learned.

## 4. Failure and Recovery

### ML Model Drift
Problem:
Behaviour may change over time.

Response:
1. Monitor model performance.
2. Collect recent trusted baseline data.
3. Retrain the model.
4. Validate the updated model.
5. Deploy the updated model.

### Network Outage
Problem:
Network telemetry may temporarily become unavailable.

Response:
1. Retain the last known security policy.
2. Avoid uncontrolled policy changes.
3. Restore network connectivity.
4. Resume telemetry collection.
5. Re-synchronise security data.

### SDN Controller Failure
Problem:
A production SDN controller may become unavailable.

Response:
1. Preserve existing enforcement state.
2. Prevent uncontrolled policy changes.
3. Restore the controller.
4. Synchronise policies.
5. Verify network segmentation.

## 5. Scalability

For larger enterprise networks:
- Deploy distributed Zeek and Suricata sensors.
- Centralise telemetry collection.
- Process ML workloads in parallel.
- Separate collection from analytics.
- Use centralised risk scoring.
- Store historical data for baseline development.
- Scale collectors according to traffic volume.

## 6. Design Trade-offs

### Isolation Forest
Chosen because it supports unsupervised anomaly detection and does not require a large labelled attack dataset.

Trade-off:
Controlled evaluation is possible, but real-world labelled attack data would be required for stronger validation.

### Zeek
Chosen for rich network metadata and behavioural analysis.

Trade-off:
It provides metadata rather than complete payload inspection.

### Suricata
Chosen for signature-based IDS capability.

Trade-off:
Signature detection depends on available rules and may not detect previously unknown behaviours without additional detection methods.

### Host Firewall Enforcement
Used for the laboratory enforcement demonstration.

Trade-off:
The prototype demonstrates host-level enforcement rather than a full enterprise SDN controller implementation.
