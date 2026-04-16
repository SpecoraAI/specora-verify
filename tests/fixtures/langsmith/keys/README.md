# LangSmith Fleet — Key Material

LangSmith Fleet does not emit per-trace cryptographic signatures.
Integrity is anchored at the TLS transport layer
(`api.smith.langchain.com`) and by the Fleet tenant's audit log.

No key material is needed for this reader. This directory exists
for structural consistency with other reader fixture directories.
