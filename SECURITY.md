<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->
# Security Policy

ISC's Security Vulnerability Disclosure Policy is documented in the
relevant [ISC Knowledgebase article][1].

## Reporting possible security issues

If you think you may be seeing a potential security vulnerability in BIND (for
example, a crash with a REQUIRE, INSIST, or ASSERT failure), please report it
immediately by [opening a confidential GitLab issue][2]. If a GitLab issue is
not an option, please use the template from the file
.gitlab/issue_templates/Security_issue.mde-mail and send it to
bind-security@isc.org.

Please do not discuss undisclosed security vulnerabilities on any public
mailing list. ISC has a long history of handling reported
vulnerabilities promptly and effectively and we respect and acknowledge
responsible reporters.

If you have a crash, you may want to consult the Knowledgebase article
entitled ["What to do if your BIND or DHCP server has crashed"][3].

## Reporting bugs

We are working with the interests of the greater Internet at heart, and
we hope you are too. In that vein, we do not offer bug bounties. If you
think you have found a bug in any ISC software, we encourage you to
[report it responsibly][2]; if verified, we will be happy to credit you
in our Release Notes.

### Use of Generative AI for Security Reports

If you actually find a problem using generative AI tools and you have verified it
yourself to be true: write the report yourself and explain the problem as you
have learned it. This makes sure the AI-generated inaccuracies and invented
issues are filtered out early before they waste more people's time.  Even if you
write the report yourself, you must make sure to reveal the fact that the
generative AI was used in your report.

As we take security reports seriously, we investigate each report with
priority. This work is both time- and energy-consuming and pulls us away from
doing other meaningful work. Fake and otherwise made-up security problems
effectively prevent us from doing real project work and make us waste time and
resources.

We ban users immediately who submit fake reports to the project.

[1]: https://kb.isc.org/docs/aa-00861
[2]: https://gitlab.isc.org/isc-projects/bind9/-/issues/new?issue[confidential]=true&issuable_template=Security_issue
[3]: https://kb.isc.org/docs/aa-00340
