package kubernetes.admission

# Rule: Deny any Pod that doesn't have a 'security' label
deny[msg] {
    input.request.kind.kind == "Pod"
    not input.request.object.metadata.labels.security
    msg := "Deployment Denied: All Pods must have a 'security' label for tracking."
}

# Rule: Deny containers that attempt to run as the 'Root' user
deny[msg] {
    input.request.kind.kind == "Pod"
    some i
    container := input.request.object.spec.containers[i]
    container.securityContext.runAsRoot == true
    msg := sprintf("Security Violation: Container '%v' is attempting to run as root!", [container.name])
}

# Rule: Deny images that don't come from a trusted registry (e.g., your company's AWS ECR)
deny[msg] {
    input.request.kind.kind == "Pod"
    some i
    container := input.request.object.spec.containers[i]
    not startswith(container.image, "your-company-registry.io/")
    msg := sprintf("Security Violation: Image '%v' is from an untrusted registry.", [container.image])
}
