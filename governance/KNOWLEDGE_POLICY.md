# Knowledge Policy

`MASTER_RULES.md` is authoritative.

Vendor knowledge must be derived from approved authoritative sources, versioned, traceable, and usable offline. Online access is for synchronization and staged updates, not a mandatory runtime dependency.

Knowledge updates follow DOWNLOAD -> STAGING -> PARSE -> DIFF -> VALIDATE -> TEST -> REVIEW -> PROMOTE. Newly downloaded material must not silently replace active validated knowledge.

Every production changeset must record vendor/product/version, knowledge version or digest, compiler version, policy-pack version, and provenance sufficient to answer why each important operation exists.