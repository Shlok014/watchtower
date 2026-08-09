# Third-Party Notices

## Loghub sample data

The files in `backend/data/samples/` are small HDFS and OpenSSH fixtures from
[Loghub](https://github.com/logpai/loghub). They are third-party data and are
not licensed under this repository's MIT license.

Loghub states that its datasets are freely available for research or academic
work. For use or distribution, it asks that users refer to the Loghub repository
and cite the Loghub paper where applicable. This repository retains only the
small fixtures needed to make the replay, parsing checks, and tests reproducible
without a download. Anyone reusing the data must evaluate the upstream terms for
their own use before doing so.

Source and citation:

- Loghub repository: <https://github.com/logpai/loghub>
- Zhu et al., *Loghub: A Large Collection of System Log Datasets for AI-driven
  Log Analytics*, ISSRE 2023.

The OpenSSH fixture can contain routable addresses and attack-related log text
from the original dataset. It is retained as research data, not as a claim about
any address or system.
