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

Remote attestation is a security process in which a computing entity, acts as the attester, provides evidence to a remote entity, acts as verifier, to demonstrate the integrity and security properties of its software, hardware, or configuration.
The evidence that genereated from the attester needs to be evaluated and verified by the verifier to determine the level of trust in the integrity and to ensure that it has not been compromised or altered.
This document specifies how to perform remote attestation via a very compact and lightweight authenticated Diffie-Hellman key exchange protocol named EDHOC (Ephemeral Diffie-Hellman Over COSE), based on RATS (Remote ATtestation procedureS) architecture.

--- middle

# Introduction

<!--Discuss remote attestation and mention some use cases.-->
Remote attestation is a security measure to verify and confirm the integiry and trustworthiness of a remote device or system in the network.
This process helps establish a level of trust in the remote system before allowing the device to join the network or some sensitive information and resources.
There are many use cases that require the use of remote attestation, such as secure boot and firmware management, cloud computing, network access control and IoT device security.

<!--Summarize RATS architecture {{RFC9334}} and main roles.-->
The IETF working group Remote ATtestation procedureS (RATS) has defined an architecture {{RFC9334}} for remote attestation, where the three main roles are the Attester, Verifier and Relying Party.
The evidence is generated from the Attester concerning its identity and integrity, which must be appraised by the Verifier for its validity.
Then the attestation results that are produced by Verifier will be used by Relying Party for purposes of reliably applying application-specific actions.

<!--Discuss the background check model and say that this specification supports the background check model.-->
One type of interaction model defined in RATS architecture is called background-check model, which is supported in this specification.
It resembles the procedure of how employers perform background checks to determine the prospective employee's trustworthiness, by contacting the respective organization that issues a report.
In this case, the employer acts as the Relying Party, the employee acts as the Attester and the organization acts as the Verifier.
The Attester conveys evidence directly to the Relying Party and the Relying Party forwards the evidence to the Verifier for appraisal.
Once the attestation result is computed by Verifier, it is sent back to the Relying Party to decide what action to take based on the attestation result.

<!--Discuss EAT-->
One way of conveying attestation evidence is the Entity Attestation Token (EAT) {{I-D.ietf-rats-eat}}.
It provides an attested claims set that describes state and characteristics of an entity, which can be used to determine the level of trust in the entity.
The word "entity" in EAT context refers to the hardware and softwares.
For example, a Trusted Execution Environment (TEE), An Internet of Things (IoT) device, an app on a smartphone or a Secure Element can all be an entity and there is no minimum security requirement to be an entity.

<!--Summarize EDHOC {{I-D.ietf-lake-edhoc}}. Mention EAD fields of EDHOC.-->
The delivery of EAT in this specification is achieved through EDHOC {{I-D.ietf-lake-edhoc}}, an Ephemeral Diffie-Hellman Over COSE protocol which is a very lightweight authenticated key exchange for highly constrained network.
In EDHOC session, the two parties involved in message exchange are referred to as the Initiator (I) and the Responder (R).
In this specification, the Attester acts as the Initiator and the Relying Party acts as the Responder.
They could transport authorization related data in the messages in an External Authorization Data field called EAD, and send EAD in dedicated fields of the four EDHOC messages (EAD_1, EAD_2, EAD_3, EAD_4).
EAT is a specific EAD item defined in this specification.

<!--Discuss implementation aspects such as the internal attestation service running on the Attester.
Root of trust. Separation between secure and non-secure worlds.-->
When it comes to implementation details, the Attester incorporates internal attestation sevices, including a specific trusted element known as the "root of trust", which serves as the starting point for establishing and validating the trustworthiness appraisals of other components.
The measurements signed by such components are referred to as the Evidence on the Attester.
This operation happens in the secure world (equivalent to Trusted Execution Environment (TEE)) of device, usually after receiving the requests from the non-secure world via the attestation API.
However, the attestation implementation detail is out of scope of this specification.

# Conventions and Definitions
{::boilerplate bcp14-tagged}

The reader is assumed to be familiar with the terms and concepts defined in EDHOC {{I-D.ietf-lake-edhoc}} and RATS {{RFC9334}}.

# Problem Description

This specification describes how to perform remote attestation over the EDHOC protocol according to the RATS architecture.
Remote attestation protocol elements are carried within EDHOC's External Authorization Data (EAD) fields.
More specifically, this specification supports the RATS background check model.
It describes how the Attester (EDHOC Initiator) and Relying Party (EDHOC Responder) complete the EDHOC handshake complemented with remote attestation protocol elements.

# Assumptions

EDHOC authentication is performed using authentication credentials which can be either signature or static Diffie-Hellman (DH) keys.
This specification makes an assumption that the EDHOC authentication credential is the same as the attestation key which is used to sign the evidence.
If the authentication credential of the EDHOC Initiator is a static DH key, then the signature of the evidence can instead be a Message Authentication Code, generated from the static-ephemeral DH shared secret between the Initiator and the Responder.

# The Protocol

## Overview

EDHOC Initiator plays the role of the RATS Attester.
EDHOC Responder plays the role of the RATS Relying Party.
An external entity, out of scope of this specification, plays the role of the RATS Verifier.

TODO: an overview figure

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

EAD_3 = EAT

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
