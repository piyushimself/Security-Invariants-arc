import { SecurityInvariant } from '../../types/invariants';

export const containerAdvancedRules: SecurityInvariant[] = [
  {
    ruleNumber: 617,
    id: "SEC-CONT-617",
    title: "Container Runtime Isolation Invariant for Supply Chain & Cosign Attestation (Variant 1)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-250"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for Supply Chain & Cosign Attestation (Variant 1)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for Supply Chain & Cosign Attestation (Variant 1), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for Supply Chain & Cosign Attestation (Variant 1), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 618,
    id: "SEC-CONT-618",
    title: "Syscall Restriction and Capability Dropping Invariant in Rootless & User Namespaces (userns) (Variant 2)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-251"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in Rootless & User Namespaces (userns) (Variant 2)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in Rootless & User Namespaces (userns) (Variant 2), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in Rootless & User Namespaces (userns) (Variant 2), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 619,
    id: "SEC-CONT-619",
    title: "Cryptographic Image Attestation and Digest Pinning for Linux Capabilities Least Privilege (Variant 3)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-252"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for Linux Capabilities Least Privilege (Variant 3)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for Linux Capabilities Least Privilege (Variant 3), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for Linux Capabilities Least Privilege (Variant 3), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 620,
    id: "SEC-CONT-620",
    title: "Read-Only Root Filesystem Boundary Invariant in Seccomp BPF Syscall Filtering (Variant 4)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-253"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in Seccomp BPF Syscall Filtering (Variant 4)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in Seccomp BPF Syscall Filtering (Variant 4), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in Seccomp BPF Syscall Filtering (Variant 4), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 621,
    id: "SEC-CONT-621",
    title: "Kernel Namespace Separation and UserNS Mapping for AppArmor & SELinux Mandatory Access Control (Variant 5)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-254"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for AppArmor & SELinux Mandatory Access Control (Variant 5)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for AppArmor & SELinux Mandatory Access Control (Variant 5), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for AppArmor & SELinux Mandatory Access Control (Variant 5), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 622,
    id: "SEC-CONT-622",
    title: "eBPF Event Interception and Anomaly Blocking for MicroVM & gVisor Sandbox Isolation (Variant 6)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-255"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for MicroVM & gVisor Sandbox Isolation (Variant 6)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for MicroVM & gVisor Sandbox Isolation (Variant 6), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for MicroVM & gVisor Sandbox Isolation (Variant 6), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 623,
    id: "SEC-CONT-623",
    title: "MicroVM Hardware Virtualization Boundary Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 7)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-256"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 7)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 7), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 7), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 624,
    id: "SEC-CONT-624",
    title: "Container Daemon Socket Access Control Invariant for Immutable Root Filesystems & tmpfs (Variant 8)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-257"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for Immutable Root Filesystems & tmpfs (Variant 8)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for Immutable Root Filesystems & tmpfs (Variant 8), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for Immutable Root Filesystems & tmpfs (Variant 8), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 625,
    id: "SEC-CONT-625",
    title: "Non-Root User UID/GID Enforcement Invariant for Container Daemon & Socket Hardening (Variant 9)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-258"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for Container Daemon & Socket Hardening (Variant 9)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for Container Daemon & Socket Hardening (Variant 9), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for Container Daemon & Socket Hardening (Variant 9), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 626,
    id: "SEC-CONT-626",
    title: "Ephemeral Secret RAM Mount Invariant for Secret Storage & Memory Namespace Protection (Variant 10)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-259"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for Secret Storage & Memory Namespace Protection (Variant 10)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for Secret Storage & Memory Namespace Protection (Variant 10), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for Secret Storage & Memory Namespace Protection (Variant 10), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 627,
    id: "SEC-CONT-627",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in Supply Chain & Cosign Attestation (Variant 11)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-260"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in Supply Chain & Cosign Attestation (Variant 11)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Supply Chain & Cosign Attestation (Variant 11), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Supply Chain & Cosign Attestation (Variant 11), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 628,
    id: "SEC-CONT-628",
    title: "Container Runtime Isolation Invariant for Rootless & User Namespaces (userns) (Variant 12)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-261"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for Rootless & User Namespaces (userns) (Variant 12)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for Rootless & User Namespaces (userns) (Variant 12), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for Rootless & User Namespaces (userns) (Variant 12), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 629,
    id: "SEC-CONT-629",
    title: "Syscall Restriction and Capability Dropping Invariant in Linux Capabilities Least Privilege (Variant 13)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-262"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in Linux Capabilities Least Privilege (Variant 13)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in Linux Capabilities Least Privilege (Variant 13), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in Linux Capabilities Least Privilege (Variant 13), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 630,
    id: "SEC-CONT-630",
    title: "Cryptographic Image Attestation and Digest Pinning for Seccomp BPF Syscall Filtering (Variant 14)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-263"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for Seccomp BPF Syscall Filtering (Variant 14)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for Seccomp BPF Syscall Filtering (Variant 14), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for Seccomp BPF Syscall Filtering (Variant 14), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 631,
    id: "SEC-CONT-631",
    title: "Read-Only Root Filesystem Boundary Invariant in AppArmor & SELinux Mandatory Access Control (Variant 15)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-264"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in AppArmor & SELinux Mandatory Access Control (Variant 15)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in AppArmor & SELinux Mandatory Access Control (Variant 15), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in AppArmor & SELinux Mandatory Access Control (Variant 15), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 632,
    id: "SEC-CONT-632",
    title: "Kernel Namespace Separation and UserNS Mapping for MicroVM & gVisor Sandbox Isolation (Variant 16)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-265"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for MicroVM & gVisor Sandbox Isolation (Variant 16)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for MicroVM & gVisor Sandbox Isolation (Variant 16), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for MicroVM & gVisor Sandbox Isolation (Variant 16), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 633,
    id: "SEC-CONT-633",
    title: "eBPF Event Interception and Anomaly Blocking for eBPF Runtime Tracing & Anomaly Detection (Variant 17)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-266"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for eBPF Runtime Tracing & Anomaly Detection (Variant 17)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for eBPF Runtime Tracing & Anomaly Detection (Variant 17), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for eBPF Runtime Tracing & Anomaly Detection (Variant 17), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 634,
    id: "SEC-CONT-634",
    title: "MicroVM Hardware Virtualization Boundary Invariant for Immutable Root Filesystems & tmpfs (Variant 18)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-267"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for Immutable Root Filesystems & tmpfs (Variant 18)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for Immutable Root Filesystems & tmpfs (Variant 18), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for Immutable Root Filesystems & tmpfs (Variant 18), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 635,
    id: "SEC-CONT-635",
    title: "Container Daemon Socket Access Control Invariant for Container Daemon & Socket Hardening (Variant 19)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-268"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for Container Daemon & Socket Hardening (Variant 19)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for Container Daemon & Socket Hardening (Variant 19), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for Container Daemon & Socket Hardening (Variant 19), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 636,
    id: "SEC-CONT-636",
    title: "Non-Root User UID/GID Enforcement Invariant for Secret Storage & Memory Namespace Protection (Variant 20)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-269"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for Secret Storage & Memory Namespace Protection (Variant 20)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for Secret Storage & Memory Namespace Protection (Variant 20), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for Secret Storage & Memory Namespace Protection (Variant 20), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 637,
    id: "SEC-CONT-637",
    title: "Ephemeral Secret RAM Mount Invariant for Supply Chain & Cosign Attestation (Variant 21)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-270"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for Supply Chain & Cosign Attestation (Variant 21)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for Supply Chain & Cosign Attestation (Variant 21), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for Supply Chain & Cosign Attestation (Variant 21), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 638,
    id: "SEC-CONT-638",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in Rootless & User Namespaces (userns) (Variant 22)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-271"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in Rootless & User Namespaces (userns) (Variant 22)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Rootless & User Namespaces (userns) (Variant 22), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Rootless & User Namespaces (userns) (Variant 22), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 639,
    id: "SEC-CONT-639",
    title: "Container Runtime Isolation Invariant for Linux Capabilities Least Privilege (Variant 23)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-272"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for Linux Capabilities Least Privilege (Variant 23)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for Linux Capabilities Least Privilege (Variant 23), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for Linux Capabilities Least Privilege (Variant 23), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 640,
    id: "SEC-CONT-640",
    title: "Syscall Restriction and Capability Dropping Invariant in Seccomp BPF Syscall Filtering (Variant 24)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-273"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in Seccomp BPF Syscall Filtering (Variant 24)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in Seccomp BPF Syscall Filtering (Variant 24), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in Seccomp BPF Syscall Filtering (Variant 24), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 641,
    id: "SEC-CONT-641",
    title: "Cryptographic Image Attestation and Digest Pinning for AppArmor & SELinux Mandatory Access Control (Variant 25)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-274"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for AppArmor & SELinux Mandatory Access Control (Variant 25)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for AppArmor & SELinux Mandatory Access Control (Variant 25), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for AppArmor & SELinux Mandatory Access Control (Variant 25), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 642,
    id: "SEC-CONT-642",
    title: "Read-Only Root Filesystem Boundary Invariant in MicroVM & gVisor Sandbox Isolation (Variant 26)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-275"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in MicroVM & gVisor Sandbox Isolation (Variant 26)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in MicroVM & gVisor Sandbox Isolation (Variant 26), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in MicroVM & gVisor Sandbox Isolation (Variant 26), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 643,
    id: "SEC-CONT-643",
    title: "Kernel Namespace Separation and UserNS Mapping for eBPF Runtime Tracing & Anomaly Detection (Variant 27)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-276"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for eBPF Runtime Tracing & Anomaly Detection (Variant 27)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for eBPF Runtime Tracing & Anomaly Detection (Variant 27), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for eBPF Runtime Tracing & Anomaly Detection (Variant 27), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 644,
    id: "SEC-CONT-644",
    title: "eBPF Event Interception and Anomaly Blocking for Immutable Root Filesystems & tmpfs (Variant 28)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-277"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for Immutable Root Filesystems & tmpfs (Variant 28)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for Immutable Root Filesystems & tmpfs (Variant 28), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for Immutable Root Filesystems & tmpfs (Variant 28), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 645,
    id: "SEC-CONT-645",
    title: "MicroVM Hardware Virtualization Boundary Invariant for Container Daemon & Socket Hardening (Variant 29)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-278"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for Container Daemon & Socket Hardening (Variant 29)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for Container Daemon & Socket Hardening (Variant 29), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for Container Daemon & Socket Hardening (Variant 29), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 646,
    id: "SEC-CONT-646",
    title: "Container Daemon Socket Access Control Invariant for Secret Storage & Memory Namespace Protection (Variant 30)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-279"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for Secret Storage & Memory Namespace Protection (Variant 30)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for Secret Storage & Memory Namespace Protection (Variant 30), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for Secret Storage & Memory Namespace Protection (Variant 30), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 647,
    id: "SEC-CONT-647",
    title: "Non-Root User UID/GID Enforcement Invariant for Supply Chain & Cosign Attestation (Variant 31)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-280"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for Supply Chain & Cosign Attestation (Variant 31)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for Supply Chain & Cosign Attestation (Variant 31), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for Supply Chain & Cosign Attestation (Variant 31), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 648,
    id: "SEC-CONT-648",
    title: "Ephemeral Secret RAM Mount Invariant for Rootless & User Namespaces (userns) (Variant 32)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-281"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for Rootless & User Namespaces (userns) (Variant 32)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for Rootless & User Namespaces (userns) (Variant 32), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for Rootless & User Namespaces (userns) (Variant 32), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 649,
    id: "SEC-CONT-649",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in Linux Capabilities Least Privilege (Variant 33)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-282"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in Linux Capabilities Least Privilege (Variant 33)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Linux Capabilities Least Privilege (Variant 33), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Linux Capabilities Least Privilege (Variant 33), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 650,
    id: "SEC-CONT-650",
    title: "Container Runtime Isolation Invariant for Seccomp BPF Syscall Filtering (Variant 34)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-283"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for Seccomp BPF Syscall Filtering (Variant 34)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for Seccomp BPF Syscall Filtering (Variant 34), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for Seccomp BPF Syscall Filtering (Variant 34), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 651,
    id: "SEC-CONT-651",
    title: "Syscall Restriction and Capability Dropping Invariant in AppArmor & SELinux Mandatory Access Control (Variant 35)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-284"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in AppArmor & SELinux Mandatory Access Control (Variant 35)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in AppArmor & SELinux Mandatory Access Control (Variant 35), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in AppArmor & SELinux Mandatory Access Control (Variant 35), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 652,
    id: "SEC-CONT-652",
    title: "Cryptographic Image Attestation and Digest Pinning for MicroVM & gVisor Sandbox Isolation (Variant 36)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-285"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for MicroVM & gVisor Sandbox Isolation (Variant 36)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for MicroVM & gVisor Sandbox Isolation (Variant 36), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for MicroVM & gVisor Sandbox Isolation (Variant 36), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 653,
    id: "SEC-CONT-653",
    title: "Read-Only Root Filesystem Boundary Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 37)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-286"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 37)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 37), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 37), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 654,
    id: "SEC-CONT-654",
    title: "Kernel Namespace Separation and UserNS Mapping for Immutable Root Filesystems & tmpfs (Variant 38)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-287"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for Immutable Root Filesystems & tmpfs (Variant 38)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for Immutable Root Filesystems & tmpfs (Variant 38), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for Immutable Root Filesystems & tmpfs (Variant 38), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 655,
    id: "SEC-CONT-655",
    title: "eBPF Event Interception and Anomaly Blocking for Container Daemon & Socket Hardening (Variant 39)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-288"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for Container Daemon & Socket Hardening (Variant 39)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for Container Daemon & Socket Hardening (Variant 39), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for Container Daemon & Socket Hardening (Variant 39), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 656,
    id: "SEC-CONT-656",
    title: "MicroVM Hardware Virtualization Boundary Invariant for Secret Storage & Memory Namespace Protection (Variant 40)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-289"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for Secret Storage & Memory Namespace Protection (Variant 40)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for Secret Storage & Memory Namespace Protection (Variant 40), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for Secret Storage & Memory Namespace Protection (Variant 40), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 657,
    id: "SEC-CONT-657",
    title: "Container Daemon Socket Access Control Invariant for Supply Chain & Cosign Attestation (Variant 41)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-290"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for Supply Chain & Cosign Attestation (Variant 41)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for Supply Chain & Cosign Attestation (Variant 41), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for Supply Chain & Cosign Attestation (Variant 41), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 658,
    id: "SEC-CONT-658",
    title: "Non-Root User UID/GID Enforcement Invariant for Rootless & User Namespaces (userns) (Variant 42)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-291"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for Rootless & User Namespaces (userns) (Variant 42)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for Rootless & User Namespaces (userns) (Variant 42), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for Rootless & User Namespaces (userns) (Variant 42), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 659,
    id: "SEC-CONT-659",
    title: "Ephemeral Secret RAM Mount Invariant for Linux Capabilities Least Privilege (Variant 43)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-292"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for Linux Capabilities Least Privilege (Variant 43)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for Linux Capabilities Least Privilege (Variant 43), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for Linux Capabilities Least Privilege (Variant 43), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 660,
    id: "SEC-CONT-660",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in Seccomp BPF Syscall Filtering (Variant 44)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-293"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in Seccomp BPF Syscall Filtering (Variant 44)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Seccomp BPF Syscall Filtering (Variant 44), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Seccomp BPF Syscall Filtering (Variant 44), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 661,
    id: "SEC-CONT-661",
    title: "Container Runtime Isolation Invariant for AppArmor & SELinux Mandatory Access Control (Variant 45)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-294"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for AppArmor & SELinux Mandatory Access Control (Variant 45)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for AppArmor & SELinux Mandatory Access Control (Variant 45), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for AppArmor & SELinux Mandatory Access Control (Variant 45), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 662,
    id: "SEC-CONT-662",
    title: "Syscall Restriction and Capability Dropping Invariant in MicroVM & gVisor Sandbox Isolation (Variant 46)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-295"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in MicroVM & gVisor Sandbox Isolation (Variant 46)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in MicroVM & gVisor Sandbox Isolation (Variant 46), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in MicroVM & gVisor Sandbox Isolation (Variant 46), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 663,
    id: "SEC-CONT-663",
    title: "Cryptographic Image Attestation and Digest Pinning for eBPF Runtime Tracing & Anomaly Detection (Variant 47)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-296"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for eBPF Runtime Tracing & Anomaly Detection (Variant 47)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for eBPF Runtime Tracing & Anomaly Detection (Variant 47), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for eBPF Runtime Tracing & Anomaly Detection (Variant 47), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 664,
    id: "SEC-CONT-664",
    title: "Read-Only Root Filesystem Boundary Invariant in Immutable Root Filesystems & tmpfs (Variant 48)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-297"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in Immutable Root Filesystems & tmpfs (Variant 48)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in Immutable Root Filesystems & tmpfs (Variant 48), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in Immutable Root Filesystems & tmpfs (Variant 48), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 665,
    id: "SEC-CONT-665",
    title: "Kernel Namespace Separation and UserNS Mapping for Container Daemon & Socket Hardening (Variant 49)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-298"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for Container Daemon & Socket Hardening (Variant 49)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for Container Daemon & Socket Hardening (Variant 49), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for Container Daemon & Socket Hardening (Variant 49), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 666,
    id: "SEC-CONT-666",
    title: "eBPF Event Interception and Anomaly Blocking for Secret Storage & Memory Namespace Protection (Variant 50)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-299"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for Secret Storage & Memory Namespace Protection (Variant 50)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for Secret Storage & Memory Namespace Protection (Variant 50), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for Secret Storage & Memory Namespace Protection (Variant 50), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 667,
    id: "SEC-CONT-667",
    title: "MicroVM Hardware Virtualization Boundary Invariant for Supply Chain & Cosign Attestation (Variant 51)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-250"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for Supply Chain & Cosign Attestation (Variant 51)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for Supply Chain & Cosign Attestation (Variant 51), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for Supply Chain & Cosign Attestation (Variant 51), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 668,
    id: "SEC-CONT-668",
    title: "Container Daemon Socket Access Control Invariant for Rootless & User Namespaces (userns) (Variant 52)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-251"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for Rootless & User Namespaces (userns) (Variant 52)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for Rootless & User Namespaces (userns) (Variant 52), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for Rootless & User Namespaces (userns) (Variant 52), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 669,
    id: "SEC-CONT-669",
    title: "Non-Root User UID/GID Enforcement Invariant for Linux Capabilities Least Privilege (Variant 53)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-252"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for Linux Capabilities Least Privilege (Variant 53)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for Linux Capabilities Least Privilege (Variant 53), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for Linux Capabilities Least Privilege (Variant 53), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 670,
    id: "SEC-CONT-670",
    title: "Ephemeral Secret RAM Mount Invariant for Seccomp BPF Syscall Filtering (Variant 54)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-253"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for Seccomp BPF Syscall Filtering (Variant 54)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for Seccomp BPF Syscall Filtering (Variant 54), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for Seccomp BPF Syscall Filtering (Variant 54), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 671,
    id: "SEC-CONT-671",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in AppArmor & SELinux Mandatory Access Control (Variant 55)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-254"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in AppArmor & SELinux Mandatory Access Control (Variant 55)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in AppArmor & SELinux Mandatory Access Control (Variant 55), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in AppArmor & SELinux Mandatory Access Control (Variant 55), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 672,
    id: "SEC-CONT-672",
    title: "Container Runtime Isolation Invariant for MicroVM & gVisor Sandbox Isolation (Variant 56)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-255"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for MicroVM & gVisor Sandbox Isolation (Variant 56)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for MicroVM & gVisor Sandbox Isolation (Variant 56), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for MicroVM & gVisor Sandbox Isolation (Variant 56), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 673,
    id: "SEC-CONT-673",
    title: "Syscall Restriction and Capability Dropping Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 57)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-256"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 57)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 57), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 57), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 674,
    id: "SEC-CONT-674",
    title: "Cryptographic Image Attestation and Digest Pinning for Immutable Root Filesystems & tmpfs (Variant 58)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-257"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for Immutable Root Filesystems & tmpfs (Variant 58)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for Immutable Root Filesystems & tmpfs (Variant 58), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for Immutable Root Filesystems & tmpfs (Variant 58), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 675,
    id: "SEC-CONT-675",
    title: "Read-Only Root Filesystem Boundary Invariant in Container Daemon & Socket Hardening (Variant 59)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-258"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in Container Daemon & Socket Hardening (Variant 59)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in Container Daemon & Socket Hardening (Variant 59), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in Container Daemon & Socket Hardening (Variant 59), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 676,
    id: "SEC-CONT-676",
    title: "Kernel Namespace Separation and UserNS Mapping for Secret Storage & Memory Namespace Protection (Variant 60)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-259"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for Secret Storage & Memory Namespace Protection (Variant 60)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for Secret Storage & Memory Namespace Protection (Variant 60), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for Secret Storage & Memory Namespace Protection (Variant 60), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 677,
    id: "SEC-CONT-677",
    title: "eBPF Event Interception and Anomaly Blocking for Supply Chain & Cosign Attestation (Variant 61)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-260"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for Supply Chain & Cosign Attestation (Variant 61)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for Supply Chain & Cosign Attestation (Variant 61), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for Supply Chain & Cosign Attestation (Variant 61), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 678,
    id: "SEC-CONT-678",
    title: "MicroVM Hardware Virtualization Boundary Invariant for Rootless & User Namespaces (userns) (Variant 62)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-261"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for Rootless & User Namespaces (userns) (Variant 62)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for Rootless & User Namespaces (userns) (Variant 62), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for Rootless & User Namespaces (userns) (Variant 62), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 679,
    id: "SEC-CONT-679",
    title: "Container Daemon Socket Access Control Invariant for Linux Capabilities Least Privilege (Variant 63)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-262"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for Linux Capabilities Least Privilege (Variant 63)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for Linux Capabilities Least Privilege (Variant 63), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for Linux Capabilities Least Privilege (Variant 63), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 680,
    id: "SEC-CONT-680",
    title: "Non-Root User UID/GID Enforcement Invariant for Seccomp BPF Syscall Filtering (Variant 64)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-263"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for Seccomp BPF Syscall Filtering (Variant 64)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for Seccomp BPF Syscall Filtering (Variant 64), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for Seccomp BPF Syscall Filtering (Variant 64), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 681,
    id: "SEC-CONT-681",
    title: "Ephemeral Secret RAM Mount Invariant for AppArmor & SELinux Mandatory Access Control (Variant 65)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-264"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for AppArmor & SELinux Mandatory Access Control (Variant 65)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for AppArmor & SELinux Mandatory Access Control (Variant 65), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for AppArmor & SELinux Mandatory Access Control (Variant 65), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 682,
    id: "SEC-CONT-682",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in MicroVM & gVisor Sandbox Isolation (Variant 66)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-265"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in MicroVM & gVisor Sandbox Isolation (Variant 66)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in MicroVM & gVisor Sandbox Isolation (Variant 66), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in MicroVM & gVisor Sandbox Isolation (Variant 66), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 683,
    id: "SEC-CONT-683",
    title: "Container Runtime Isolation Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 67)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-266"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 67)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 67), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 67), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 684,
    id: "SEC-CONT-684",
    title: "Syscall Restriction and Capability Dropping Invariant in Immutable Root Filesystems & tmpfs (Variant 68)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-267"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in Immutable Root Filesystems & tmpfs (Variant 68)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in Immutable Root Filesystems & tmpfs (Variant 68), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in Immutable Root Filesystems & tmpfs (Variant 68), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 685,
    id: "SEC-CONT-685",
    title: "Cryptographic Image Attestation and Digest Pinning for Container Daemon & Socket Hardening (Variant 69)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-268"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for Container Daemon & Socket Hardening (Variant 69)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for Container Daemon & Socket Hardening (Variant 69), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for Container Daemon & Socket Hardening (Variant 69), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 686,
    id: "SEC-CONT-686",
    title: "Read-Only Root Filesystem Boundary Invariant in Secret Storage & Memory Namespace Protection (Variant 70)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-269"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in Secret Storage & Memory Namespace Protection (Variant 70)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in Secret Storage & Memory Namespace Protection (Variant 70), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in Secret Storage & Memory Namespace Protection (Variant 70), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 687,
    id: "SEC-CONT-687",
    title: "Kernel Namespace Separation and UserNS Mapping for Supply Chain & Cosign Attestation (Variant 71)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-270"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for Supply Chain & Cosign Attestation (Variant 71)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for Supply Chain & Cosign Attestation (Variant 71), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for Supply Chain & Cosign Attestation (Variant 71), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 688,
    id: "SEC-CONT-688",
    title: "eBPF Event Interception and Anomaly Blocking for Rootless & User Namespaces (userns) (Variant 72)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-271"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for Rootless & User Namespaces (userns) (Variant 72)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for Rootless & User Namespaces (userns) (Variant 72), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for Rootless & User Namespaces (userns) (Variant 72), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 689,
    id: "SEC-CONT-689",
    title: "MicroVM Hardware Virtualization Boundary Invariant for Linux Capabilities Least Privilege (Variant 73)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-272"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for Linux Capabilities Least Privilege (Variant 73)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for Linux Capabilities Least Privilege (Variant 73), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for Linux Capabilities Least Privilege (Variant 73), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 690,
    id: "SEC-CONT-690",
    title: "Container Daemon Socket Access Control Invariant for Seccomp BPF Syscall Filtering (Variant 74)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-273"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for Seccomp BPF Syscall Filtering (Variant 74)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for Seccomp BPF Syscall Filtering (Variant 74), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for Seccomp BPF Syscall Filtering (Variant 74), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 691,
    id: "SEC-CONT-691",
    title: "Non-Root User UID/GID Enforcement Invariant for AppArmor & SELinux Mandatory Access Control (Variant 75)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-274"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for AppArmor & SELinux Mandatory Access Control (Variant 75)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for AppArmor & SELinux Mandatory Access Control (Variant 75), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for AppArmor & SELinux Mandatory Access Control (Variant 75), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 692,
    id: "SEC-CONT-692",
    title: "Ephemeral Secret RAM Mount Invariant for MicroVM & gVisor Sandbox Isolation (Variant 76)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-275"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for MicroVM & gVisor Sandbox Isolation (Variant 76)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for MicroVM & gVisor Sandbox Isolation (Variant 76), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for MicroVM & gVisor Sandbox Isolation (Variant 76), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 693,
    id: "SEC-CONT-693",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 77)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-276"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 77)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 77), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in eBPF Runtime Tracing & Anomaly Detection (Variant 77), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 694,
    id: "SEC-CONT-694",
    title: "Container Runtime Isolation Invariant for Immutable Root Filesystems & tmpfs (Variant 78)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-277"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for Immutable Root Filesystems & tmpfs (Variant 78)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for Immutable Root Filesystems & tmpfs (Variant 78), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for Immutable Root Filesystems & tmpfs (Variant 78), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 695,
    id: "SEC-CONT-695",
    title: "Syscall Restriction and Capability Dropping Invariant in Container Daemon & Socket Hardening (Variant 79)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-278"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in Container Daemon & Socket Hardening (Variant 79)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in Container Daemon & Socket Hardening (Variant 79), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in Container Daemon & Socket Hardening (Variant 79), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 696,
    id: "SEC-CONT-696",
    title: "Cryptographic Image Attestation and Digest Pinning for Secret Storage & Memory Namespace Protection (Variant 80)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-279"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for Secret Storage & Memory Namespace Protection (Variant 80)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for Secret Storage & Memory Namespace Protection (Variant 80), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for Secret Storage & Memory Namespace Protection (Variant 80), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 697,
    id: "SEC-CONT-697",
    title: "Read-Only Root Filesystem Boundary Invariant in Supply Chain & Cosign Attestation (Variant 81)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-280"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in Supply Chain & Cosign Attestation (Variant 81)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in Supply Chain & Cosign Attestation (Variant 81), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in Supply Chain & Cosign Attestation (Variant 81), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 698,
    id: "SEC-CONT-698",
    title: "Kernel Namespace Separation and UserNS Mapping for Rootless & User Namespaces (userns) (Variant 82)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-281"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for Rootless & User Namespaces (userns) (Variant 82)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for Rootless & User Namespaces (userns) (Variant 82), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for Rootless & User Namespaces (userns) (Variant 82), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 699,
    id: "SEC-CONT-699",
    title: "eBPF Event Interception and Anomaly Blocking for Linux Capabilities Least Privilege (Variant 83)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-282"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for Linux Capabilities Least Privilege (Variant 83)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for Linux Capabilities Least Privilege (Variant 83), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for Linux Capabilities Least Privilege (Variant 83), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 700,
    id: "SEC-CONT-700",
    title: "MicroVM Hardware Virtualization Boundary Invariant for Seccomp BPF Syscall Filtering (Variant 84)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-283"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for Seccomp BPF Syscall Filtering (Variant 84)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for Seccomp BPF Syscall Filtering (Variant 84), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for Seccomp BPF Syscall Filtering (Variant 84), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 701,
    id: "SEC-CONT-701",
    title: "Container Daemon Socket Access Control Invariant for AppArmor & SELinux Mandatory Access Control (Variant 85)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-284"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for AppArmor & SELinux Mandatory Access Control (Variant 85)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for AppArmor & SELinux Mandatory Access Control (Variant 85), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for AppArmor & SELinux Mandatory Access Control (Variant 85), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 702,
    id: "SEC-CONT-702",
    title: "Non-Root User UID/GID Enforcement Invariant for MicroVM & gVisor Sandbox Isolation (Variant 86)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-285"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for MicroVM & gVisor Sandbox Isolation (Variant 86)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for MicroVM & gVisor Sandbox Isolation (Variant 86), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for MicroVM & gVisor Sandbox Isolation (Variant 86), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 703,
    id: "SEC-CONT-703",
    title: "Ephemeral Secret RAM Mount Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 87)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-286"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 87)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 87), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 87), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 704,
    id: "SEC-CONT-704",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in Immutable Root Filesystems & tmpfs (Variant 88)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-287"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in Immutable Root Filesystems & tmpfs (Variant 88)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Immutable Root Filesystems & tmpfs (Variant 88), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Immutable Root Filesystems & tmpfs (Variant 88), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 705,
    id: "SEC-CONT-705",
    title: "Container Runtime Isolation Invariant for Container Daemon & Socket Hardening (Variant 89)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-288"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for Container Daemon & Socket Hardening (Variant 89)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for Container Daemon & Socket Hardening (Variant 89), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for Container Daemon & Socket Hardening (Variant 89), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 706,
    id: "SEC-CONT-706",
    title: "Syscall Restriction and Capability Dropping Invariant in Secret Storage & Memory Namespace Protection (Variant 90)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-289"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in Secret Storage & Memory Namespace Protection (Variant 90)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in Secret Storage & Memory Namespace Protection (Variant 90), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in Secret Storage & Memory Namespace Protection (Variant 90), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 707,
    id: "SEC-CONT-707",
    title: "Cryptographic Image Attestation and Digest Pinning for Supply Chain & Cosign Attestation (Variant 91)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-290"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for Supply Chain & Cosign Attestation (Variant 91)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for Supply Chain & Cosign Attestation (Variant 91), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for Supply Chain & Cosign Attestation (Variant 91), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 708,
    id: "SEC-CONT-708",
    title: "Read-Only Root Filesystem Boundary Invariant in Rootless & User Namespaces (userns) (Variant 92)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-291"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in Rootless & User Namespaces (userns) (Variant 92)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in Rootless & User Namespaces (userns) (Variant 92), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in Rootless & User Namespaces (userns) (Variant 92), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 709,
    id: "SEC-CONT-709",
    title: "Kernel Namespace Separation and UserNS Mapping for Linux Capabilities Least Privilege (Variant 93)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-292"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for Linux Capabilities Least Privilege (Variant 93)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for Linux Capabilities Least Privilege (Variant 93), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for Linux Capabilities Least Privilege (Variant 93), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 710,
    id: "SEC-CONT-710",
    title: "eBPF Event Interception and Anomaly Blocking for Seccomp BPF Syscall Filtering (Variant 94)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-293"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for Seccomp BPF Syscall Filtering (Variant 94)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for Seccomp BPF Syscall Filtering (Variant 94), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for Seccomp BPF Syscall Filtering (Variant 94), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 711,
    id: "SEC-CONT-711",
    title: "MicroVM Hardware Virtualization Boundary Invariant for AppArmor & SELinux Mandatory Access Control (Variant 95)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-294"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"MicroVM Hardware Virtualization Boundary Invariant for AppArmor & SELinux Mandatory Access Control (Variant 95)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for MicroVM Hardware Virtualization Boundary Invariant for AppArmor & SELinux Mandatory Access Control (Variant 95), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for MicroVM Hardware Virtualization Boundary Invariant for AppArmor & SELinux Mandatory Access Control (Variant 95), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 712,
    id: "SEC-CONT-712",
    title: "Container Daemon Socket Access Control Invariant for MicroVM & gVisor Sandbox Isolation (Variant 96)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "MicroVM & gVisor Sandbox Isolation",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["gVisor runsc / Kata Containers", "CIS-Docker-Benchmark-1.0", "CWE-295"],
    formalInvariant: "\u2200 c \u2208 Containers(MicroVM & gVisor Sandbox Isolation), Run(c) \u21d2 EnforceInvariant(\"Container Daemon Socket Access Control Invariant for MicroVM & gVisor Sandbox Isolation (Variant 96)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(MicroVM & gVisor Sandbox Isolation)",
                "meaning": "Running containerized workload within MicroVM & gVisor Sandbox Isolation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under MicroVM & gVisor Sandbox Isolation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in MicroVM & gVisor Sandbox Isolation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-microvm\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Daemon Socket Access Control Invariant for MicroVM & gVisor Sandbox Isolation (Variant 96), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to gVisor runsc / Kata Containers\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-microvm\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per gVisor runsc / Kata Containers."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against MicroVM & gVisor Sandbox Isolation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-microvm"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running MicroVM & gVisor Sandbox Isolation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Daemon Socket Access Control Invariant for MicroVM & gVisor Sandbox Isolation (Variant 96), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 713,
    id: "SEC-CONT-713",
    title: "Non-Root User UID/GID Enforcement Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 97)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "eBPF Runtime Tracing & Anomaly Detection",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["Tetragon eBPF / Falco Rules", "CIS-Docker-Benchmark-2.0", "CWE-296"],
    formalInvariant: "\u2200 c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection), Run(c) \u21d2 EnforceInvariant(\"Non-Root User UID/GID Enforcement Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 97)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(eBPF Runtime Tracing & Anomaly Detection)",
                "meaning": "Running containerized workload within eBPF Runtime Tracing & Anomaly Detection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under eBPF Runtime Tracing & Anomaly Detection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in eBPF Runtime Tracing & Anomaly Detection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-ebpf\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Non-Root User UID/GID Enforcement Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 97), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Tetragon eBPF / Falco Rules\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-ebpf\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Tetragon eBPF / Falco Rules."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against eBPF Runtime Tracing & Anomaly Detection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-ebpf"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running eBPF Runtime Tracing & Anomaly Detection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Non-Root User UID/GID Enforcement Invariant for eBPF Runtime Tracing & Anomaly Detection (Variant 97), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 714,
    id: "SEC-CONT-714",
    title: "Ephemeral Secret RAM Mount Invariant for Immutable Root Filesystems & tmpfs (Variant 98)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Immutable Root Filesystems & tmpfs",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 5.12", "CIS-Docker-Benchmark-3.0", "CWE-297"],
    formalInvariant: "\u2200 c \u2208 Containers(Immutable Root Filesystems & tmpfs), Run(c) \u21d2 EnforceInvariant(\"Ephemeral Secret RAM Mount Invariant for Immutable Root Filesystems & tmpfs (Variant 98)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Immutable Root Filesystems & tmpfs)",
                "meaning": "Running containerized workload within Immutable Root Filesystems & tmpfs execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Immutable Root Filesystems & tmpfs strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Immutable Root Filesystems & tmpfs environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-immutable\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Ephemeral Secret RAM Mount Invariant for Immutable Root Filesystems & tmpfs (Variant 98), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 5.12\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-immutable\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 5.12."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Immutable Root Filesystems & tmpfs.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-immutable"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Immutable Root Filesystems & tmpfs, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Ephemeral Secret RAM Mount Invariant for Immutable Root Filesystems & tmpfs (Variant 98), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 715,
    id: "SEC-CONT-715",
    title: "Seccomp Default-Deny Syscall Whitelist Invariant in Container Daemon & Socket Hardening (Variant 99)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Container Daemon & Socket Hardening",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["CIS Docker Benchmark 2.1", "CIS-Docker-Benchmark-4.0", "CWE-298"],
    formalInvariant: "\u2200 c \u2208 Containers(Container Daemon & Socket Hardening), Run(c) \u21d2 EnforceInvariant(\"Seccomp Default-Deny Syscall Whitelist Invariant in Container Daemon & Socket Hardening (Variant 99)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Container Daemon & Socket Hardening)",
                "meaning": "Running containerized workload within Container Daemon & Socket Hardening execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Container Daemon & Socket Hardening strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Container Daemon & Socket Hardening environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-container\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Container Daemon & Socket Hardening (Variant 99), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to CIS Docker Benchmark 2.1\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-container\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per CIS Docker Benchmark 2.1."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Container Daemon & Socket Hardening.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-container"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Container Daemon & Socket Hardening, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Seccomp Default-Deny Syscall Whitelist Invariant in Container Daemon & Socket Hardening (Variant 99), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 716,
    id: "SEC-CONT-716",
    title: "Container Runtime Isolation Invariant for Secret Storage & Memory Namespace Protection (Variant 100)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Secret Storage & Memory Namespace Protection",
    difficulty: "Expert",
    standardType: "Defense-in-Depth",
    standards: ["NIST SP 800-190", "CIS-Docker-Benchmark-5.0", "CWE-299"],
    formalInvariant: "\u2200 c \u2208 Containers(Secret Storage & Memory Namespace Protection), Run(c) \u21d2 EnforceInvariant(\"Container Runtime Isolation Invariant for Secret Storage & Memory Namespace Protection (Variant 100)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Secret Storage & Memory Namespace Protection)",
                "meaning": "Running containerized workload within Secret Storage & Memory Namespace Protection execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Secret Storage & Memory Namespace Protection strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Secret Storage & Memory Namespace Protection environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-secret\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Container Runtime Isolation Invariant for Secret Storage & Memory Namespace Protection (Variant 100), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to NIST SP 800-190\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-secret\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per NIST SP 800-190."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Secret Storage & Memory Namespace Protection.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-secret"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Secret Storage & Memory Namespace Protection, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Container Runtime Isolation Invariant for Secret Storage & Memory Namespace Protection (Variant 100), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 717,
    id: "SEC-CONT-717",
    title: "Syscall Restriction and Capability Dropping Invariant in Supply Chain & Cosign Attestation (Variant 101)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Supply Chain & Cosign Attestation",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SLSA Level 4 / Sigstore", "CIS-Docker-Benchmark-1.0", "CWE-250"],
    formalInvariant: "\u2200 c \u2208 Containers(Supply Chain & Cosign Attestation), Run(c) \u21d2 EnforceInvariant(\"Syscall Restriction and Capability Dropping Invariant in Supply Chain & Cosign Attestation (Variant 101)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Supply Chain & Cosign Attestation)",
                "meaning": "Running containerized workload within Supply Chain & Cosign Attestation execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Supply Chain & Cosign Attestation strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Supply Chain & Cosign Attestation environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-supply\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Syscall Restriction and Capability Dropping Invariant in Supply Chain & Cosign Attestation (Variant 101), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SLSA Level 4 / Sigstore\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-supply\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SLSA Level 4 / Sigstore."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Supply Chain & Cosign Attestation.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-supply"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Supply Chain & Cosign Attestation, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Syscall Restriction and Capability Dropping Invariant in Supply Chain & Cosign Attestation (Variant 101), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 718,
    id: "SEC-CONT-718",
    title: "Cryptographic Image Attestation and Digest Pinning for Rootless & User Namespaces (userns) (Variant 102)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Rootless & User Namespaces (userns)",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["OCI Runtime Spec / Linux userns", "CIS-Docker-Benchmark-2.0", "CWE-251"],
    formalInvariant: "\u2200 c \u2208 Containers(Rootless & User Namespaces (userns)), Run(c) \u21d2 EnforceInvariant(\"Cryptographic Image Attestation and Digest Pinning for Rootless & User Namespaces (userns) (Variant 102)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Rootless & User Namespaces (userns))",
                "meaning": "Running containerized workload within Rootless & User Namespaces (userns) execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Rootless & User Namespaces (userns) strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Rootless & User Namespaces (userns) environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-rootless\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Cryptographic Image Attestation and Digest Pinning for Rootless & User Namespaces (userns) (Variant 102), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to OCI Runtime Spec / Linux userns\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-rootless\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per OCI Runtime Spec / Linux userns."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Rootless & User Namespaces (userns).",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-rootless"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Rootless & User Namespaces (userns), security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Cryptographic Image Attestation and Digest Pinning for Rootless & User Namespaces (userns) (Variant 102), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 719,
    id: "SEC-CONT-719",
    title: "Read-Only Root Filesystem Boundary Invariant in Linux Capabilities Least Privilege (Variant 103)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Linux Capabilities Least Privilege",
    difficulty: "Advanced",
    standardType: "Defense-in-Depth",
    standards: ["POSIX Capabilities / CIS Benchmark", "CIS-Docker-Benchmark-3.0", "CWE-252"],
    formalInvariant: "\u2200 c \u2208 Containers(Linux Capabilities Least Privilege), Run(c) \u21d2 EnforceInvariant(\"Read-Only Root Filesystem Boundary Invariant in Linux Capabilities Least Privilege (Variant 103)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Linux Capabilities Least Privilege)",
                "meaning": "Running containerized workload within Linux Capabilities Least Privilege execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Linux Capabilities Least Privilege strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Linux Capabilities Least Privilege environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-linux\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Read-Only Root Filesystem Boundary Invariant in Linux Capabilities Least Privilege (Variant 103), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to POSIX Capabilities / CIS Benchmark\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-linux\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per POSIX Capabilities / CIS Benchmark."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Linux Capabilities Least Privilege.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-linux"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Linux Capabilities Least Privilege, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Read-Only Root Filesystem Boundary Invariant in Linux Capabilities Least Privilege (Variant 103), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 720,
    id: "SEC-CONT-720",
    title: "Kernel Namespace Separation and UserNS Mapping for Seccomp BPF Syscall Filtering (Variant 104)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "Seccomp BPF Syscall Filtering",
    difficulty: "Expert",
    standardType: "Mandatory Standard",
    standards: ["Linux Seccomp BPF / CWE-250", "CIS-Docker-Benchmark-4.0", "CWE-253"],
    formalInvariant: "\u2200 c \u2208 Containers(Seccomp BPF Syscall Filtering), Run(c) \u21d2 EnforceInvariant(\"Kernel Namespace Separation and UserNS Mapping for Seccomp BPF Syscall Filtering (Variant 104)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(Seccomp BPF Syscall Filtering)",
                "meaning": "Running containerized workload within Seccomp BPF Syscall Filtering execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under Seccomp BPF Syscall Filtering strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in Seccomp BPF Syscall Filtering environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-seccomp\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for Kernel Namespace Separation and UserNS Mapping for Seccomp BPF Syscall Filtering (Variant 104), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to Linux Seccomp BPF / CWE-250\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-seccomp\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per Linux Seccomp BPF / CWE-250."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against Seccomp BPF Syscall Filtering.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-seccomp"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running Seccomp BPF Syscall Filtering, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for Kernel Namespace Separation and UserNS Mapping for Seccomp BPF Syscall Filtering (Variant 104), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  },
  {
    ruleNumber: 721,
    id: "SEC-CONT-721",
    title: "eBPF Event Interception and Anomaly Blocking for AppArmor & SELinux Mandatory Access Control (Variant 105)",
    domain: "containers",
    domainName: "Container Security",
    subdomain: "AppArmor & SELinux Mandatory Access Control",
    difficulty: "Advanced",
    standardType: "Mandatory Standard",
    standards: ["SELinux MCS / AppArmor Profile", "CIS-Docker-Benchmark-5.0", "CWE-254"],
    formalInvariant: "\u2200 c \u2208 Containers(AppArmor & SELinux Mandatory Access Control), Run(c) \u21d2 EnforceInvariant(\"eBPF Event Interception and Anomaly Blocking for AppArmor & SELinux Mandatory Access Control (Variant 105)\") \u2227 NonPrivileged(c) = TRUE \u2227 SyscallAuditPass(c) = TRUE",
    symbolBreakdown: [
          {
                "symbol": "c \u2208 Containers(AppArmor & SELinux Mandatory Access Control)",
                "meaning": "Running containerized workload within AppArmor & SELinux Mandatory Access Control execution environment"
          },
          {
                "symbol": "NonPrivileged(c)",
                "meaning": "Strict non-root user execution with zero ambient root Linux capabilities"
          },
          {
                "symbol": "SyscallAuditPass(c)",
                "meaning": "eBPF or Seccomp policy verifies zero forbidden or unprofiled system calls"
          }
    ],
    plainEnglish: "This invariant guarantees that every container instance managed under AppArmor & SELinux Mandatory Access Control strictly enforces sandbox confinement, drops unnecessary Linux capabilities, isolates namespaces, and verifies image provenance before invocation.",
    whyItMatters: "Container breakouts in AppArmor & SELinux Mandatory Access Control environments permit adversaries to compromise the underlying host kernel, mount root storage partitions, sniff cross-tenant pod networks, and harvest cloud provider node credentials.",
    vulnerableExample: {
          "language": "yaml",
          "code": "# VULNERABLE: Privileged container execution with host namespace sharing\napiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-apparmor\nspec:\n  containers:\n  - name: app\n    image: app:latest # Tag not pinned by digest!\n    securityContext:\n      privileged: true # Root on host!\n      allowPrivilegeEscalation: true",
          "explanation": "Fails the container invariant for eBPF Event Interception and Anomaly Blocking for AppArmor & SELinux Mandatory Access Control (Variant 105), granting excessive host privileges."
    },
    secureExample: {
          "language": "yaml",
          "code": "# SECURE: Hardened non-root sandbox conforming to SELinux MCS / AppArmor Profile\napiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-apparmor\nspec:\n  containers:\n  - name: app\n    image: app@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069\n    securityContext:\n      privileged: false\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      runAsUser: 10001\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault",
          "explanation": "Implements strict capability stripping and non-root execution per SELinux MCS / AppArmor Profile."
    },
    howToTest: {
          "tools": [
                "trivy",
                "cosign",
                "falco",
                "kube-bench"
          ],
          "steps": [
                "Run static image and configuration analysis against AppArmor & SELinux Mandatory Access Control.",
                "Attempt privileged syscall invocation (e.g., ptrace, mount) inside container.",
                "Verify runtime drops attempt and generates Falco/Tetragon high-severity alert."
          ],
          "commandExample": "trivy image --severity HIGH,CRITICAL --security-checks config,vuln secure-apparmor"
    },
    interviewChallenge: {
          "scenario": "During a production audit of a multi-tenant container cluster running AppArmor & SELinux Mandatory Access Control, security engineers observe containers running with default capabilities and root user IDs.",
          "question": "According to the invariant for eBPF Event Interception and Anomaly Blocking for AppArmor & SELinux Mandatory Access Control (Variant 105), what is the critical threat posed by root execution in containers even without the '--privileged' flag, and how is it addressed?",
          "hint": "Consider Linux kernel capabilities such as CAP_NET_RAW and CAP_DAC_OVERRIDE, plus shared kernel vulnerabilities.",
          "sampleAnswer": "Even without '--privileged', running as UID 0 gives the container process dangerous default capabilities (such as CAP_NET_RAW for packet spoofing and CAP_CHOWN). Furthermore, any local privilege escalation vulnerability in the shared Linux kernel immediately grants host root access. The invariant requires user namespaces (userns), explicit 'runAsNonRoot: true', and dropping all capabilities ('ALL').",
          "keyTakeaway": "Containers do not contain by default; hard isolation requires User Namespaces, non-root execution, and explicit capability stripping."
    }
  }
];
