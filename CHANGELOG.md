# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
# [0.1.11] - 2023-05-17

###

- Fixed Usage: output inconsistensies
- Added hyperlink to https://docs.openziti.io/
- Added debug output in both ingress and egress for traffic that matches
  host initiated connections
- standardized on debug output messaging and corrected spelling errors.

# [0.1.10] - 2023-05-17

###

- Reverted ci/release.yml to include 'Pre-Depends: linux-image-generic (>= 5.15.0)'
- Fixed README Missing comma in json sample


# [0.1.9] - 2023-05-17

- Changed ci/release.yml to include 'Pre-Depends: linux-image-generic (>= 5.15.0)'
- Fixed ci/release.yml ${{ env.MAINTAINER }} missing prepended $
- Added additional src/dest debug info in outbound tracking for udp
- Fixed inconsistency in usage:

###

- Fixed --help output changed "ssh echo" to ssh

# [0.1.8] - 2023-05-17

###

- Added input validation to all interface related commands.  If non existent name is given "Interface not 
  found: <ifname> will be output.
- Fixed output of zfw -L -i
- Added README.md section for containers, fixed some inconsistensies  

# [0.1.7] - 2023-05-17

###

- Fixed input validation to regect any tc filter commands with out -z, --direction specified
- Added enhanced output for outbound tracking 
- Modified tcp state map to have separate fin state for client and server to more accuratly
  identify tcp session close.
- Edits to readme removed ./ and repeated sudo

# [0.1.6] - 2023-05-17

###

-Fixed start_ebpf.py syntax error printf() and should have been print() and removed sys.exit(1) on zfw -Q fail.
-Fixed README.md inconsistencies/errors.
-Fixed zfw -Q not displaying sudo permissions requirement when operated as a non privileged user.
-Modified Maximums entries for mutiple maps, this included a changed for MAX_BPF_ENTRIES which
 is settable at compile time and reflected in release.yml/ci.yml workload.
 
# [0.1.5] - 2023-05-16

###

- Fixed some README.md inconsistencies and reduced some instructions to list only the most optimal methods.
- Changed Depends: ziti-edge-tunnel to Pre-Depends: ziti-edge-tunnel '(>= 0.21.0)' in release.yml key to .deb 
  control to prevent installation if ziti-edge-tunnel is not already installed.

# [0.1.4] - 2023-05-16

###

- Refactored release.yml to replace depricated actions.

# [0.1.3] - 2023-05-15

###

- Added abilitiy to override automated settings in start_ebpf.sh by moving user_rules.sh read to last item in script

## [0.1.2] - 2023-05-15

###

- Refactored release.yml deploy_packages_(arch) jobs to a single deploy_packages job with iteration through ${{ matrix.goarch }}

## [0.1.1] - 2023-05-15

###

- Added initial code. 
- Added README.md
- Added BUILD.md
- Modified json object in files/json/ebpf_config.json and modified files/scripts/start_ebpf.py to parse it for new key "ExternalInterfaces" which
  gives the abilty to assign an outbound tracking object and set per interface rules on a wan interface as described in README.md
- Fixed memory leak caused b y not calling json_object_put() on the root json objects created by calls to json _token_parse(). 

## [0.1.0] - 2023-05-12

###

- Added initial code.

