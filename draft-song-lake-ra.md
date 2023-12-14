---
title: "Remote attestation over EDHOC"
abbrev: "RA-EDHOC"
category: std

docname: draft-song-lake-ra-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Lightweight Authenticated Key Exchange"
keyword: Internet-Draft
coding: utf-8
venue:
  group: "Lightweight Authenticated Key Exchange"
  type: "Working Group"
  mail: "lake@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/lake/"
  github: "ysong02/RemoteAttestation_overEDHOC"
  latest: "https://ysong02.github.io/RemoteAttestation_overEDHOC/draft-song-lake-ra.html"

author:
 -
    fullname: Yuxuan Song
    ins: Y. Song
    organization: Inria
    email: "yuxuan.song@inria.fr"

normative:
    I-D.ietf-lake-edhoc:
    I-D.ietf-rats-eat:

informative:
    RFC9334:


--- abstract

TODO What is remote attestation?
Remote attesation is an essential process before the device can be admitted to join the network.
The evidence that genereated from the device needs to be evaluated and verified to assure their integrity and trustworthiness.
This document specifies the remote attestation process by which the evidence is conveyed during the handshake in EDHOC (Ephemeral Diffie-Hellman Over COSE, a very compact and lightweight key exchange protocol), applied on the background-check model in RATS (Remote ATtestation ProcedureS) architecture.

--- middle

# Introduction

Discuss remote attestation and mention some use cases.

Summarize RATS architecture {{RFC9334}} and main roles. Discuss the background check model and say that this specification supports the background check model.

One way of conveying attestation evidence is the Entity Attestation Token (EAT) {{I-D.ietf-rats-eat}}. Discuss EAT.

Summarize EDHOC {{I-D.ietf-lake-edhoc}}. Mention EAD fields of EDHOC.

Discuss implementation aspects such as the internal attestation service running on the Attester.
Root of trust. Separation between secure and non-secure worlds. How the attestation is implemented is out of scope of this specification.

# Conventions and Definitions
The reader is assumed to be familiar with the vocabulary and concepts defined in EDHOC {{I-D.ietf-lake-edhoc}} and RATS {{RFC9334}}.

Define succinct versions of the RATS terms. See draft-fossati-tls-attestation-04 Section 2.

{::boilerplate bcp14-tagged}

# Problem Description

This specification describes how to perform remote attestation over the EDHOC protocol according to the RATS architecture.
Remote attestation protocol elements are carried within EDHOC's External Authorization Data (EAD) fields.
More specifically, this specification supports the RATS background check model.
It describes how the Attester (EDHOC Initiator) and Relying Party (EDHOC Responder) complete the EDHOC handshake complemented with remote attestation protocol elements.

# Assumptions

EDHOC authentication is performed using authentication credentials which can be either signature or static Diffie-Hellman (DH) keys.
This specification makes an assumption that the EDHOC authentication credential is the same as the attestation key which is used to sign the evidence.
If the authentication credential of the EDHOC Initiator is a static DH key, then the signature of the evidence can instead be a Message Authentication Code, generated from the static-ephemeral DH shared secret between the Initiator and the Responder.

We assume that the roles of

# The Protocol

EDHOC Initiator plays the role of the RATS Attester.
EDHOC Responder plays the role of the RATS Relying Party.
An external entity, out of scope of this specification, plays the role of the RATS Verifier.

The Attester and the Relying Party communicate by transporting messages within EDHOC's External Authorization Data (EAD) fields.

## External Authorization Data 1

In EAD_1, the Attester transports the Proposed_Evidence_Type object.
Evidence_Type signals to the Relying Party the proposal to do remote attestation, as well as which attestation claims the Attester supports.
The supported attestation claims are encoded in CBOR in the form of a sequence.

TODO: Encode Proposed_Evidence_Type as CBOR data structure. See draft-ietf-lake-authz for examples.
TODO: Register with IANA EAD_1 label

## External Authorization Data 2

In EAD_2, the Relying Party signals to the Attester the supported and requested attestation claims.
In case the attestation is not supported, the EDHOC Responder returns an error message.
EAD_2 carries the Request_Attestation object.
Similarly to EAD_1, Request_Attestation object is encoded in CBOR.

TODO: Encode Request_Attestation as CBOR data structure.
TODO: Register with IANA EAD_2 label.

Once the Attester receives EAD_2, it makes a request to its local attestation API to perform attestation.
It uses the nonce generated from the EDHOC handshake, with the following parameters:

* exporter_label is TBD4.
* context is an empty byte string.
* length is 16 bytes.

nonce = EDHOC_Exporter(exporter_label, context, length).

Nonce is passed to the attestation API and used to generate the attestation evidence.
Note that the nonce is not carried in the message, but is rather signed as

## External Authorization Data 3

As a response to the attestation request, the local attestation service returns the serialized EAT.


# Security Considerations

TODO: Security considerations


# IANA Considerations

TODO1: Register EAD_1 label. See draft-ietf-lake-authz for an example.
TODO2: Register EAD_2 label
TODO3: Register EAD_3 label
TODO4: Register EDHOC_Exporter label

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
