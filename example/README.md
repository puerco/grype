# OpenVEX Turbocharged Grype Demo

This fork contains a turbocharged `grype` scanner that understands OpenVEX and
can use it to enhance its security scans. It is not meant to be a full vex
implementation but a POC on how OpenVEX can work in grype.

# Clone and Run 

To run these examples, ensure that you have go 1.19 or newer installed, and
clone this repository to you local machine:

```
[puerco@babieco /tmp]❯ git clone git@github.com:puerco/grype.git
Cloning into 'grype'...
remote: Enumerating objects: 8515, done.
remote: Counting objects: 100% (1377/1377), done.
remote: Compressing objects: 100% (352/352), done.
remote: Total 8515 (delta 1156), reused 1126 (delta 1022), pack-reused 7138
Receiving objects: 100% (8515/8515), 3.70 MiB | 7.12 MiB/s, done.
Resolving deltas: 100% (5541/5541), done.

[puerco@babieco /tmp] ❯ cd grype/

[puerco@babieco grype] on  main 🦆❯ git switch openvex-poc 
branch 'openvex-poc' set up to track 'origin/openvex-poc'.
Switched to a new branch 'openvex-poc'

[puerco@babieco grype] on  main 🦆❯ go run . --help
A vulnerability scanner for container images, filesystems, and SBOMs.
[... output trimmed]

```

## Understanding a false positive

Lets consider the following image: 

```
alpine@sha256:b6ca290b6b4cdcca5b3db3ffa338ee0285c11744b4a6abaa9627746ee3291d8d
```

If we check its configuration using
[crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md),
we can see that this image is the linux amd64 variant of alpine:

```shell
crane config alpine@sha256:b6ca290b6b4cdcca5b3db3ffa338ee0285c11744b4a6abaa9627746ee3291d8d | jq -r '"\(.os)/\(.architecture)"'
linux/amd64
```

Run grype (this fork or stock) to check its vulnerabilities:

```
go run . alpine@sha256:b6ca290b6b4cdcca5b3db3ffa338ee0285c11744b4a6abaa9627746ee3291d8d
 ✔ Vulnerability DB        [no update available]
 ✔ Loaded image            
 ✔ Parsed image            
 ✔ Cataloged packages      [16 packages]
 ⠸ Scanning image...       [4 vulnerabilities]
 ✔ Scanning image...       [4 vulnerabilities]
   ├── 0 critical, 2 high, 2 medium, 0 low, 0 negligible
   └── 4 fixed

NAME        INSTALLED  FIXED-IN  TYPE  VULNERABILITY  SEVERITY 
libcrypto3  3.0.8-r3   3.0.8-r4  apk   CVE-2023-1255  Medium    
libcrypto3  3.0.8-r3   3.0.9-r0  apk   CVE-2023-2650  High      
libssl3     3.0.8-r3   3.0.8-r4  apk   CVE-2023-1255  Medium    
libssl3     3.0.8-r3   3.0.9-r0  apk   CVE-2023-2650  High    
```

The results report two vulnerabilities CVE-2023-1255 and CVE-2023-2650.

Now checking the
[NVD entry for CVE-2023-1255](https://nvd.nist.gov/vuln/detail/CVE-2023-1255),
we can see that this vulnerability can only be exploited in the AES-XTS
arm64 implementation:

> The AES-XTS cipher decryption implementation for 64 bit ARM platform contains
> a bug that could cause it to read past the input buffer, leading to a crash. 

This is a false positive as our image is the amd64 variant.

Let's send OpenVEX to the rescue :rocket:

## Creating an OpenVEX document to mute the alert

Let's create a VEX document to turn off the scanner alert:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/example/puerco/vex-grype-demo-1",
  "author": "Puerco J. Cerdo",
  "role": "Security Researcher",
  "timestamp": "2023-06-06T20:26:03.647787998-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2023-1255",
      "products": [
        "pkg:oci/alpine@sha256%3Ab6ca290b6b4cdcca5b3db3ffa338ee0285c11744b4a6abaa9627746ee3291d8d"
      ],
      "subcomponents": [
        "pkg:apk/alpine/libcrypto3@3.0.8-r3?arch=x86_64&upstream=openssl&distro=alpine-3.17.3",
        "pkg:apk/alpine/libssl3@3.0.8-r3?arch=x86_64&upstream=openssl&distro=alpine-3.17.3"
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "This image is the amd64 variant of alpine. CVE-2023-1255 only affects arm64"
    }
  ]
}
```

The important part in this OpenVEX document is the VEX statement. Let's break it
down to understand its parts:

* `vulnerability` is the CVE identifier (CVE-2023-1255).
* The `products` list includes one purl: The identifier for the image we are talking about. This
is the VEX product, the piece of software this VEX document is talking about.
* The `subcomponents` list enumerates two alpine packages: `libcrypto3` and `libssl3`. These
packages are reported above by grype and are matched to CVE-2023-1255.
* `status` is the [VEX status](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-labels), `not_affected`. This is what we want to communicate 
to the scanner.
* `justification` is a [machine readable label](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications) that lets readers know the reason why
the author thinks the vulnerability does not affect the product.
* The `impact_statement` field has human readable text that the reader can present
to human users to let them know more about the VEX assessment.
 
Save the file (or use the [sample](alpine-demo.openvex.json ) found in this
examples directory) and feed it to the modified grype scanner using the `--vex`
flag:

```
go run . alpine@sha256:b6ca290b6b4cdcca5b3db3ffa338ee0285c11744b4a6abaa9627746ee3291d8d --vex=./example/alpine-demo.openvex.json 

 ✔ Vulnerability DB        [no update available]
 ✔ Loaded image            
 ✔ Parsed image            
 ✔ Cataloged packages      [16 packages]
 ⠸ Scanning image...       [4 vulnerabilities]
 ✔ Scanning image...       [4 vulnerabilities]
   ├── 0 critical, 2 high, 2 medium, 0 low, 0 negligible
   └── 4 fixed

NAME        INSTALLED  FIXED-IN  TYPE  VULNERABILITY  SEVERITY 
libcrypto3  3.0.8-r3   3.0.9-r0  apk   CVE-2023-2650  High      
libssl3     3.0.8-r3   3.0.9-r0  apk   CVE-2023-2650  High      


OPENVEX REPORT
==============

These scanning results exclude vulnerabilities using VEX data:

VULNERABILITY  STATUS        JUSTIFICATION                        COMPONENT                          
  CVE-2023-1255  not_affected  vulnerable_code_not_in_execute_path  pkg:apk/alpine/libcrypto3@3.0.8-r3  
                                                                    pkg:apk/alpine/libssl3@3.0.8-r3     
```

Using the data contained in the VEX document, grype will now exclude from its
results the entry for CVE-2023-1255. As you see above, this modified grype fork
also prints a simple report explaining why the vulnerability was left out of
the scanning results.
