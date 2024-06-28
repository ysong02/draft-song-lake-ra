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
    I-D.ietf-rats-eat:
    RFC9528:
informative:
    RFC9334:
    RFC8949:
    RFC8392:
    IANA.CWT.Claims: IANA.cwt
    I-D.tschofenig-rats-psa-token:
    IANA-CoAP-Content-Formats:
      title: CoAP Content-Formats
      target: https://www.iana.org/assignments/core-parameters
    I-D.ietf-lake-authz:
    I-D.ietf-rats-ar4si:
--- abstract

This document specifies how to perform remote attestation as part of the lightweight authenticated Diffie-Hellman key exchange protocol EDHOC (Ephemeral Diffie-Hellman Over COSE), based on the Remote ATtestation procedureS (RATS) architecture.

--- middle

# Introduction

<!--Discuss remote attestation and mention some use cases.-->
Remote attestation is a security process which verifies and confirms the integrity and trustworthiness of a remote device or system in the network.
This process helps establish a level of trust in the remote system before allowing the device to e.g. join the network or access some sensitive information and resources.
The use cases that require remote attestation include secure boot and firmware management, cloud computing, network access control, etc.

<!--Summarize RATS architecture {{RFC9334}} and main roles.-->
The IETF working group Remote ATtestation procedureS (RATS) has defined an architecture {{RFC9334}} for remote attestation.
The three main roles in the RATS architecture are the Attester, the Verifier and the Relying Party.
The Attester generates the evidence concerning its identity and integrity, which must be appraised by the Verifier for its validity.
Then, the Verifier produces the attestation result, which is consequently used by the Relying Party for the purposes of reliably applying application-specific actions.

<!--Discuss the two RATS models and say that this specification supports the background check model.-->
One type of interaction model defined in the RATS architecture is called the background-check model.
It resembles the procedure of how employers perform background checks to determine the prospective employee's trustworthiness, by contacting the respective organization that issues a report.
In this case, the employer acts as the Relying Party, the employee acts as the Attester and the organization acts as the Verifier.
The Attester conveys evidence directly to the Relying Party and the Relying Party forwards the evidence to the Verifier for appraisal.
Once the attestation result is computed by the Verifier, it is sent back to the Relying Party to decide what action to take based on the attestation result.
Another model is called passport model, in which the Attester communicates directly with the Verifier.
The Attester gives the evidence to the Verifier and gets the attestation result from the Verifier.
THen the Attester conveys the attestation result to the Relying Party.
EDHOC can support both background-check model and passport model to perform remote attestation.
This specification employs both the RATS background-check model and the passport model.

<!--Discuss EAT-->
One way of conveying attestation evidence is the Entity Attestation Token (EAT) {{I-D.ietf-rats-eat}}.
It provides an attested claims set that describes the state and the characteristics of the Attester, which can be used to determine its level of trustworthiness.
This specification relies on the EAT as the format for attestation evidence.

<!--Summarize EDHOC {{RFC9528}}. Mention EAD fields of EDHOC.-->
Ephemeral Diffie-Hellman over COSE (EDHOC) {{RFC9528}} is a lightweight authenticated key exchange protocol for highly constrained networks.
In EDHOC, the two parties involved in the key exchange are referred to as the Initiator (I) and the Responder (R).
EDHOC supports the transport of external authorization data, through the dedicated EAD fields.
This specification delivers EAT through EDHOC.
Specifically, EAT is transported as an EAD item.

<!--Discuss implementation aspects such as the internal attestation service running on the Attester.
Root of trust. Separation between secure and non-secure worlds.-->
Typically, the Attester incorporates an internal attestation service, including a specific trusted element known as the "root of trust".
Root of trust serves as the starting point for establishing and validating the trustworthiness appraisals of other components on the system.
The measurements signed by the attestation service are referred to as the Evidence.
The signing is requested through an attestation API.
How the components are separated between the secure and non-secure worlds on a device is out of scope of this specification.

# Conventions and Definitions
{::boilerplate bcp14-tagged}

The reader is assumed to be familiar with the terms and concepts defined in EDHOC {{RFC9528}} and RATS {{RFC9334}}.

# Problem Description

This specification describes how to perform remote attestation over the EDHOC protocol according to the RATS architecture.
Remote attestation protocol elements are carried within EDHOC's External Authorization Data (EAD) fields.
More specifically, this specification supports the RATS background-check model.
It considers three cases:
1.Remote attestation with EDHOC Initiator as an Attester and EDHOC Responder as a Relying Party.
2.Reverse attestation over reverse EDHOC message flow (see {{Appendix A.2.2 of RFC9528}}).
EDHOC Initiator acts as a Relying Party and EDHOC Responder acts as an Attester.
3.Mutual attestation.
The specification describes how the Attester EDHOC Initiator and EDHOC Responder complete the EDHOC handshake complemented with remote attestation protocol elements in the above cases.

# Assumptions

The details of the protocol between Relying Party and Verifier are out of the scope.
The only assumption is that the Verifier outputs a fresh nonce and that same nonce is passed on to the EDHOC session.
That is where the link between the two protocols comes in.
The remainder, such as the evidence type selection is just the negotiation.
In general, the Verifier is supposed to know how to verify more than one format of the evidence type.
Therefore, the Verifier MUST send back at least one format to the Relying Party.
We assume in this specification, the Relying Party also has knowledge about the Attester, so it can narrow down the type selection and send to the Attester only one format of evidence type.


The Attester should have an explicit relation with the Verifier, such as from device manufacuture, so that the Verifier can evaluate the Evidence that is produced by the Attester.
The authentication between the Attester and the Relying Party is performed with EDHOC {{RFC9528}} and defines the process of remote attestation using the External Authorization Data (EAD) fields defined in EDHOC.

# The Protocol {#protocol}

## Forward remote attestation {#forward}

A common use case for forward remote attestation is to attest an IoT device to a network server.
For example, doing remote attestation to verify that the latest version of firmware is running on the IoT device before the network server allows it to join the network (see {{firmware}}).

### Background-check model {#forward-background}

An overview of doing forward remote attestation over EDHOC is indicated in {{fig-forward-attestation}}.
EDHOC session is between the Attester and the Relying Party in background-check model.
EDHOC Initiator plays the role of the RATS Attester.
EDHOC Responder plays the role of the RATS Relying Party.
The Attester and the Relying Party communicate by transporting messages within EDHOC's External Authorization Data (EAD) fields.
An external entity, out of scope of this specification, plays the role of the RATS Verifier.

Remote attestation starts with an Attestation proposal in EAD_1 by providing the supported evidence types from the Attester.
The Relying Party generates an Attestation request in EAD_2 based on the selected evidence type and the nonce from the Verifier, then sends it to the Attester.
The Attester calls its attestation service to generate the evidence according to the Attestation request.
The evidence is sent as an EAT in EAD_3 from the Attester to the Relying Party.
The Relying Party treats the evidence as an opaque data and sends it to the Verifier.
The Verifier consumes the evidence and generates an attestation result, which is then sent back to the Relying Party.

~~~~~~~~~~~ aasvg
+----------+              +-----------+
|  EDHOC   |              |   EDHOC   |
| Initiator|              | Responder |
+----------+ Attestation  +-----------+               +----------+
|          | proposal     |           |   Provided    |          |
| Attester +------------->|  Relying  | EvidenceTypes | Verifier |
|          |              |           +-------------->|          |
|          |              |   Party   |<--------------+          |
|          |<-------------+           |   Selected    |          |
|          | Attestation  |           |EvidenceType(s)|          |
|          | request      |           |               |          |
|   (A)    |              |   (RP)    |               |   (V)    |
|          | Evidence     |           |   Evidence    |          |
|          +------------->|           +-------------->|          |
|          |              |           |<--------------+          |
|          |              |           |  Attestation  |          |
|          |              |           |  result       |          |
+----------+              +-----------+               +----------+
           <-------------->
            EDHOC session
~~~~~~~~~~~
{: #fig-forward-attestation title="Overview of forward remote attestation. EDHOC is used between A and RP. The link between V and RP is out of scope of this specification." artwork-align="center"}

## Reverse attestation {#reverse}

One use case for reverse attestation is when a network server needs to attest itself to a client (e.g., an IoT device).
For example, the client needs to submit some sensitive data to the network server, which requires the network server to be attested first.
In reverse attestation, the network server acts as an Attester and the client is the Relying Party.

### Background-check model {#reverse-background}

In this section, the reverse attestation in background-check model is performed over reverse EDHOC message flow (see {{Appendix A.2.2 of RFC9528}}).
EDHOC session is between the Relying Party and the Attester.
The Relying Party triggers a new EDHOC session with a Uri-Path: "/.well-known/edhoc".
EDHOC message_1 is then sent from the Attester with an attestation proposal carried in EAD_1.
The Attestation request is carried in EAD_2 and the evidence is carried in EAD_3.

~~~~~~~~~~~ aasvg
                           +-----------+               +-----------+
                           |   EDHOC   |               |   EDHOC   |
                           | Responder |               | Initiator |
+----------+               +-----------+               +-----------+
|          |               |           |  (trigger)    |           |
| Verifier |               |  Relying  +-------------->|  Attester |
|          |               |           | Attestation   |           |
|          |   Provided    |   Party   | proposal      |           |
|          | EvidenceTypes |           |<--------------+           |
|          |<--------------+           |               |           |
|          +-------------->|           |               |           |
|   (V)    |   Selected    |   (RP)    +-------------->|    (A)    |
|          |EvidenceType(s)|           | Attestation   |           |
|          |               |           | request       |           |
|          |               |           |               |           |
|          | Evidence      |           | Evidence      |           |
|          |<--------------+           |<--------------+           |
|          +-------------->|           |               |           |
|          | Attestation   |           |               |           |
|          | result        |           |               |           |
+----------+               +-----------+               +-----------+
                                       <--------------->
                                         EDHOC session
~~~~~~~~~~~
{: #fig-reverse-attestation-background title="Overview of reverse attestation in background-check model. EDHOC is used between RP and A. The link between V and RP is out of scope of this specification." artwork-align="center"}

### Passport model

In this section, the reverse attestation in passport model is performed over reverse EDHOC message flow (see {{Appendix A.2.2 of RFC9528}}).
EDHOC session is between the Relying Party and the Attester.
The Relying Party requires the attestation result from the Attester.
Before sending the attestation result to the Relying Party, the Attester has to contact to the Verifier to get the attestation result.
The EAD items for passport model are defined in {{ead-items}}.
EDHOC message_1 is sent from the Attester with a result proposal carried in EAD_1.
The result proposal contains a list of trusted Verifiers by the Attester, with the type of Verifier identity and the Verifier identity data.
The result request is sent by the Relying Party carried in EAD_2, including a selected Verifier identity type, Verifier identity data and nonce.
The attestation result is carried in EAD_3.

~~~~~~~~~~~ aasvg
+-----------+               +-----------+
|   EDHOC   |               |   EDHOC   |
| Responder |               | Initiator |
+-----------+               +-----------+               +----------+
|           |  (trigger)    |           |               |          |
|  Relying  +-------------->|  Attester |               | Verifier |
|           | Result        |           |               |          |
|   Party   | proposal      |           |               |          |
|           |<--------------+           |               |          |
|           |               |           |               |          |
|           |               |           |               |          |
|   (RP)    +-------------->|    (A)    |               |   (V)    |
|           | Result        |           | Result request|          |
|           | request       |           +-------------->|          |
|           |               |           |<--------------+          |
|           | Result        |           | Result        |          |
|           |<--------------+           |               |          |
|           |               |           |               |          |
|           |               |           |               |          |
|           |               |           |               |          |
+-----------+               +-----------+               +----------+
            <--------------->
              EDHOC session
~~~~~~~~~~~
{: #fig-reverse-attestation-passport title="Overview of reverse attestation in passport model. EDHOC is used between RP and A. The link between V and RP is out of scope of this specification." artwork-align="center"}

## Mutual attestation {#mutual-attestation}

### Background-check model -- Background-check model

In the case that both entities (e.g., an IoT device and a network server) need to attest to each other, they can perform a mutual attestation to establish a bidirectional trust.
Ensuring that both the IoT device and the network server are trusted before exchanging sensitive information.



~~~~~~~~~~~ aasvg
                           +-----------+              +-----------+
                           |   EDHOC   |              |   EDHOC   |
                           | Initiator |              | Responder |
+----------+               +-----------+ Attestation  +-----------+               +----------+
|          |               |           | proposal     |           |   Provided    |          |
| Verifier |               | Attester  +------------->|  Relying  | EvidenceTypes | Verifier |
|          |               |           |              |           +-------------->|          |
|          |               |           | Attestation  |   Party   |<--------------+          |
|          |   Provided    |    (A)    | request      |   (RP)    |   Selected    |          |
|          | EvidenceTypes |           |<-------------+           |EvidenceType(s)|          |
|          |<--------------+     /     | Attestation  |     /     |               |          |
|          +-------------->|           | proposal     |           |               |          |
|   (V)    |   Selected    |  Relying  |              | Attester  |               |   (V)    |
|          |EvidenceType(s)|           | Evidence     |           |  Evidence     |          |
|          |               |   Party   +------------->|           +-------------->|          |
|          |               |   (RP)    | Attestation  |    (A)    |<--------------+          |
|          |               |           | request      |           |  Attestation  |          |
|          |   Evidence    |           |              |           |  result       |          |
|          |<--------------+           |<-------------+           |               |          |
|          +-------------->|           | Evidence     |           |               |          |
|          |  Attestation  |           |              |           |               |          |
+----------+  result       +-----------+              +-----------+               +----------+
                                       <-------------->
                                        EDHOC session
~~~~~~~~~~~
{: #fig-mutual-attestation title="Overview of mutual attestation of Background-check model in both sides. EDHOC is used between A and RP. The link between V and RP is out of scope of this specification." artwork-align="center"}

### Background-check model -- Passport model
TBD

~~~~~~~~~~~ aasvg
+-----------+              +-----------+
|   EDHOC   |              |   EDHOC   |
| Initiator |              | Responder |
+-----------+ Attestation  +-----------+               +----------+               +----------+
|           | proposal     |           |   Provided    |          |               |          |
| Attester  +------------->|  Relying  | EvidenceTypes | Verifier |               | Verifier |
|           |              |           +-------------->|          |               |          |
|           | Attestation  |   Party   |<--------------+          |               |          |
|    (A)    | request      |   (RP)    |   Selected    |          |               |          |
|           |<-------------+           |EvidenceType(s)|          |               |          |
+     /     | Result       |     /     |               |          |               |          |
|           | proposal     |           |               |          |               |          |
|  Relying  |              | Attester  |               |   (V)    |               |          |
|           | Evidence     |           |  Evidence     |          | Result request|          |
|   Party   +------------->|           +-------------->| ---------+-------------->|          |
|   (RP)    | Result       |    (A)    |<--------------+          |               |          |
|           | request      |           |  Attestation  |          |               |          |
|           |              |           |  result       |          |               |          |
+           |<-------------+           |<--------------+----------+---------------+          |
|           | Result       |           |               |          |  Result       |          |
|           |              |           |               |          |               |          |
+-----------+              +-----------+               +----------+               +----------+
            <-------------->
             EDHOC session
~~~~~~~~~~~
{: #fig-mutual-attestation-BP title="Overview of mutual attestation of Background-check model -- Passport model. EDHOC is used between A and RP. The link between V and RP is out of scope of this specification." artwork-align="center"}

## External Authorization Data (EAD) items {#ead-items}

EDHOC {{RFC9528}} supports one or more EAD items in each EAD field.
EAD item is a CBOR sequence of an ead_label and an optional ead_value.

### Attestation_proposal {#attestation-proposal}

To start a remote attestation in background-check model, the Attester transports the Proposed_EvidenceType object.
It signals to the Relying Party the proposal to do remote attestation, as well as which attestation claims the Attester supports.
The supported attestation claims are encoded in CBOR in the form of a sequence.

The EAD item for an attestation proposal is:

* ead_label = TBD1
* ead_value = Attestation_proposal, which is a CBOR byte string:

~~~~~~~~~~~~~~~~
Attestation_proposal = bstr .cbor Proposed_EvidenceType

Proposed_EvidenceType = (
	content-format: 	[ + uint]
)
~~~~~~~~~~~~~~~~

where

* content-format is an array that contains all the supported evidence types by the Attester.
* There MUST be at least one item in the array.
* content-format is an indicator of the format type (e.g., application/eat+cwt with an appropriate eat_profile parameter set).

The sign of ead_label MUST be negative to indicate that the EAT item is critical.
If the receiver cannot recognize the critical EAD item, or cannot process the information in the critical EAD item, then the receiver MUST send an EDHOC error message back.


### Attestation_request {#attestation-request}

As a response to the attestation proposal, the Relying Party signals to the Attester the supported and requested evidence type.
In case none of the evidence types is supported, the Relying Party rejects the first message_1 with an error indicating support for another evidence type.

The EAD item for an attestation request is:

* ead_label = TBD2
* ead_value = Attestation_request, which is a CBOR byte string:

~~~~~~~~~~~~~~~~
Attestation_request = bstr .cbor Selected_EvidenceType
Selected_EvidenceType = (
	content-format:uint,
	nonce:bstr
)
~~~~~~~~~~~~~~~~

where

* content-format is the selected evidence type by the Relying Party and supported by the Verifier.
* nonce is generated by the Verifier and forwarded by the Relying Party.

### Evidence {#evidence}

As a response to the attestation request, the Attester calls its local attestation service to generate and return the serialized EAT {{I-D.ietf-rats-eat}} as Evidence.

The EAD item is:

* ead_label = TBD3
* ead_value is a serialized EAT.

### Result_proposal {#result-proposal}

In passport model, the attestation result is transfered from the Attester to the Relying Party.
Before sending the attestation result, the Attester needs to negotiate with the Relying Party the Verifier identities from which it should get the attestation result.
The Attester firstly sends an attestation result proposal which contains the type of the Verifier identity (e.g., a public key, a certificate, a unique identifier...) and the Verifier identity.

The EAD item for an attestation result proposal is:

* ead_label = TBD4
* ead_value = Result_proposal, which is a CBOR byte string:

~~~~~~~~~~~~~~~~
Result_proposal = bstr .cbor Proposed_VerfierIdentity
Proposed_VerifierIdentity = [ + VerifierIdentity ]

VerifierIdentity = (
	identity_type: uint,
	identity: bstr
)
~~~~~~~~~~~~~~~~

where

* Proposed_VerifierIdentity is defined as a list of one or more VerifierIdentity elements.
* Each VerifierIdentity within the list contains
    * identity_type: An unsigned integer representing the type of the Verifier identity.
    * identity: A byte string containing the actual identity data.

### Result_request {#result-request}

As a response to the attestation result proposal, the Relying Party signals to the Attester the trusted Verifier.
In case none of the Verifiers can be trusted by the Relying Party, the session is aborted.
Relying Party generates a nonce to ensure the freshness of the attestation result from the Verifier.

The EAD item for an attestation result request is:

* ead_label = TBD5
* ead_value = Result_request, which is a CBOR byte string:

~~~~~~~~~~~~~~~~
Result_request = bstr .cbor Request_structure

Request_structure = {
  selected_verifier: VerfierIdentity,
  nonce: bstr
}
~~~~~~~~~~~~~~~~

### Result {#result}

The attestation result is generated and signed by the Verifier as a serialized EAT {{I-D.ietf-rats-eat}}.
The Relying Party can decide what action to take with regards to the Attester based on the information elements in attetation result.
One way for encoding the attestation result is defined by the RATS working group {{I-D.ietf-rats-ar4si}}.

The EAD item is:

* ead_label = TBD6
* ead_value is a serialized EAT.

# Error Handling

This section specifies a new EDHOC error code and how it is used in the proposed protocol.

## EDHOC Error "Attestation failed"

This section specifies a new EDHOC error "Attetation failed".
The format of the error message follows the one in EDHOC protocol(see {{Section 6 of RFC9528}}).

~~~~~~~~~~~ aasvg
+----------+----------------+----------------------------------------+
| ERR_CODE | ERR_INFO Type  | Description                            |
+==========+================+========================================+
|     TBD4 | attestation    | Attestation failed                     |
+----------+----------------+----------------------------------------+
~~~~~~~~~~~
{: #fig-error title="EDHOC error code and error information for Attestation failed."}

Error code TBD4 indicates to the receiver that the remote attestation is failed after the evidence is sent.
This can occur in two cases:

1. The Verifier evaluates the attestation evidence and returns a negative result based on the Verifier's appraisal policy.

2. The Verifier provides a positive attestation result to the Relying Party, but the Relying Party can not establish a sufficient level of trust to proceed decision-specific actions based on its appraisal policy.

In case 1, the Verifier signals the error to the Relying Party, which then generates an EDHOC "Attestation failed" error and send it to the Attester.
In case 2, the Relying Party directly generates and sends the "Attestation failed" error to the Attester.
The application decides how to handle the error message.

# Security Considerations

This specification is performed over EDHOC {{RFC9528}} by using EDHOC's EAD fields.
The privacy considerations of EADs in EDHOC apply to this specification.

EAD_1 is not resistant to either active attackers or passive attackers, because neither the Initiator nor the Responder has been authenticated.

Although EAD_2 is encrypted, the Initiator has not been authenticated, rendering EAD_2 vulnerable against the active attackers.

The evidence type(s) in EAD_1 and EAD_2 MAY be very specific and potentially reveal sensitive information about the device.
The leaking of the evidence type in EAD_1 and/or EAD_2 MAY risk to be used by the attackers for malicious purposes.
Data in EAD_3 and EAD_4 are protected between the Initiator and the Responder in EDHOC.

Mutual attestation carries a lower risk for EAD items when the Responder is the Attester.
Only the Attestation_proposal in EAD_2 is not protected to active attackers.
Both the attestation_request in EAD_3 and the evidence in EAD_4 are protected.

# IANA Considerations

## EDHOC External Authorization Data Registry

IANA is requested to register the following entry in the "EDHOC External Authorization Data" registry under the group name "Ephemeral Diffie-Hellman Over Cose (EDHOC)".
The ead_label = TBD1 corresponds to the ead_value Attestation_proposal with processing specified in {{attestation-proposal}}.
The ead_label = TBD2 corresponds to the ead_value Attestation_request in {{attestation-request}}.
The ead_label = TBD3 corresponds to the ead_value which carries the EAT, as specified in {{evidence}}.
The ead_lable = TBD4 corresponds to the ead_value Result_proposal in passport model in {{result-proposal}}.
The ead_lable = TBD5 corresponds to the ead_value Result_request in passport model in {{result-request}}.
The ead_lable = TBD6 corresponds to the ead_value Result in passport model in {{result}}.

| Label | Value Type | Description |
| TBD1 | bstr | Attestation Proposal |
| TBD2 | bstr | Attestation Request |
| TBD3 | bstr | Evidence for remote attestation |
| TBD4 | bstr | Result Proposal |
| TBD5 | bstr | Result Proposal |
| TBD6 | bstr | Attestation result |
{: #ead-table title="Addition to the EDHOC EAD registry" cols="r l l"}

--- back

# Example: Remote Attestation Flow

~~~~aasvg

.--------------------------.
|     EDHOC Initiator      |       .-------------------.
+--------------------------+       |  EDHOC Responder  |
| Attestation   | Attester |       +-------------------+   .----------.
| Service       |          |       |  Relying Party    |   | Verifier |
'--+----------------+------'       '---------+---------'   '-----+----'
   |                |                        |                   |
   |                |                        |                   |
   |                |EDHOC message_1         |                   |
   |                |  {...}                 |                   |
   |                |  EAD_1(                |                   |
   |                |    types(a,b,c)        |                   |
   |                |  )                     |                   |
   |                +----------------------->|                   |
   |                |                        |                   |
   |                |                        |  /newSession      |
   |                |                        +------------------>|
   |                |                        |                   |
   |                |                        |                   |
   |                |                        | Body: {           |
   |                |                        |   nonce,          |
   |                | EDHOC message_2        |   types(a,b)      |
   |                |  {...}                 | }                 |
   |                |  EAD_2(                |<------------------+
   |                |    nonce,              |                   |
   |                |    type(a)             |                   |
   |                |  )                     |                   |
   |                |  Auth_CRED(Sig/MAC)    |                   |
   |                |<-----------------------+                   |
   |   Body:{       |                        |                   |
   |    nonce,      |                        |                   |
   |    type(a)     |                        |                   |
   |   }            |                        |                   |
   |<---------------+                        |                   |
   | Body:{         |                        |                   |
   |   nonce,       |                        |                   |
   |   Evidence     |                        |                   |
   | }              |                        |                   |
   +--------------->|                        |                   |
   |                | EDHOC message_3        |                   |
   |                |  {...}                 |                   |
   |                |  EAT(nonce,Evidence)   |                   |
   |                |  Auth_CRED(sig/MAC)    |                   |
   |                +----------------------->|                   |
   |                |                        |                   |
   |                |                        |                   |
   |                |                        |                   |
   |                |                        | Body: {           |
   |                |                        |  EAT}             |
   |                |                        +------------------>|
   |                |                        | Body: {           |
   |                |                        |  att-result: AR{} |
   |                |                        | }                 |
   |                |                        |<------------------+
   |                |                        +---.               |
   |                |                        |    | verify AR{}  |
   |                |                        |<--'               |
   |                |                        |                   |
   |                |    application data    |                   |
   |                |<---------------------->|                   |
   |                |                        |                   |
~~~~
{: #figure-iot-example title="Example of remote attestation."}

# Remote attestation in parallel with enrollment authorization

This section discusses the possibility of doing remote attestation in parallel with the enrollment authorization procedure defined in {{I-D.ietf-lake-authz}}.
In this case, the message count is much decreased.

The detailed procedure is TBD.

# Example: Firmware Version {#firmware}

The goal in this example is to verify that the firmware running on the device is the latest version, and is neither tampered or compromised.
A device acts as the Attester, currently in an untrusted state.
The Attester needs to generate the Evidence to attest itself.
A gateway that can communicate with the Attester and can control its access to the network acts as the Relying Party.
The gateway will finally decide whether the device can join the network or not depending on the Attestation Result.
The Attestation Result is produced by the Verifier, which is a web server that can be seen as the manufacturer of the device.
Therefore it can appraise the Evidence that is sent by the Attester.
The remote attestation session starts with the Attester sending EAD_1 in EDHOC message 1, as specified in {{attestation-proposal}}.
In EAD_1 field, the Attester indicates that the format of EAT is in CWT and the profile of EAT is Platform Security Architecture (PSA) attestation token {{I-D.tschofenig-rats-psa-token}}.
PSA attestation token contains the claims relating to the security state of the platform, which are provided by PSA's Initial Attestation API.

Therefore, the EAD_1 in EDHOC message_1 is:

~~~~~~~~~~~~~~~~
{
    content-format: [66,61]
}
~~~~~~~~~~~~~~~~

According to {{I-D.tschofenig-rats-psa-token}}, IANA is requested to register the Content-Format ID in the "CoAP Content-Formats" registry {{IANA-CoAP-Content-Formats}}, for the `application/eat+cwt` media type witih tihe `eat_profile` parameter equal to `tag:psacertified.org,2023:psa#tfm`. We assume the ID that is assigned to this content type is 66.

The Media Type equivalent is:

~~~~~~~~~~~~~~~~
media-type: application/eat+cwt; eat_profile="tag:psacertified.org,2023:psa#tfm"
~~~~~~~~~~~~~~~~

If the Verifier and the Relying Party can support this evidence type that is proposed by the Attester, the Relying Party will include in the EAD_2 field the same evidence type, alongside a nonce for message freshness.

~~~~~~~~~~~~~~~~
{
    content-format: 66,
    nonce: h'1385b9708109c7fb'
}
~~~~~~~~~~~~~~~~

The Evidence in EAD_3 field is the Platform Security Architecture (PSA) attestation token, which is the attestation of the platform state to assure the firmware integrity.
This can be generated from Measured boot, which creates the measurements of loaded code and data during the boot process and make them part of an overall chain of trust.
Each stage of the chain of trust stores the measurements in a local root of trust, then the Root of Trust for Report (RTR) of the device can use them as materials to generate the Evidence.
The components of the Evidence should at least be:

~~~~~~~~~~~~~~~~
{
    /psa-boot-seed/                     2397: h'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
    /eat_nonce/                         10: h'1385b9708109c7fb',
    /psa-client-id/                     2394: 3002,
    /psa-certificate-reference/         2398: "0604565272829-10010",
    /psa-implementation-id/             2396: h'aaaaaaaaabbbbbbbbbbbbbccccccccccccccdddddddddddddd',
    /ueid/                              256: h'01fa58755f658627ce5460f29b75296713248cae7ad9e2984b90280efcbcb50248',
    /eat_profile/                       265: 66,
    /psa-security-lifecycle/            2395: 12288,
    /psa-software-components/           2399: [
                                               {
                                                 /measurement-desc/  6: "SHA256",
                                                 /measurement-value/ 2: h'e33ea1e002d2fe794d1a1679db58bb6a23a8f659bb77f89c458cecf9d5995ffd',
                                                 /signer-id/         5: h'bfe6d86f8826f4ff97fb96c4e6fbc4993e4619fc565da26adf34c329489adc38',
                                                 /measurement-type/  1: "SPE",
                                                 /version/           4: "1.6.0",
                                               },
                                               {
                                                                     6: "SHA256",
                                                                     2: h'087d13c68f32aaafb8c4fc0a2253445432009765e216fb85c398c9580522c1bf',
                                                                     5: h'b360caf5c98c6b942a4882fa9d4823efb166a9ef6a6e4aa37c1919ed1fccc049',
                                                                     1: "NSPE",
                                                                     4: "0.0.0",
                                               },
                                              ],
    /psa-verification-service-indicator/ 2400: "www.trustedfirmware.org",
}
~~~~~~~~~~~~~~~~

The key for signature is:
~~~~~~~~~~~~~~~~
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEP//suV+AhafEDh0+p5C+9Ot4zdd9WFA6ZMFgD5GzPnoAoGCCqGSM49
AwEHoUQDQgAETl4iCZ47zrRbRG0TVf0dw7VFlHtv18HInYhnmMNybo+A1wuECyVq
rDSmLt4QQzZPBECV8ANHS5HgGCCSr7E/Lg==
-----END EC PRIVATE KEY-----
~~~~~~~~~~~~~~~~

The resulting COSE object is:

~~~~~~~~~~~~~~~~~
18([
  h'A10126',
  {},
  h'aa19095d5820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0a481385b9708109c7fb19095a190bba19095e73303630343536353237323832392d313030313019095c5819aaaaaaaaabbbbbbbbbbbbbccccccccccccccdddddddddddddd190100582101fa58755f658627ce5460f29b75296713248cae7ad9e2984b90280efcbcb50248190109184219095b19300019095f82a50666534841323536025820e33ea1e002d2fe794d1a1679db58bb6a23a8f659bb77f89c458cecf9d5995ffd055820bfe6d86f8826f4ff97fb96c4e6fbc4993e4619fc565da26adf34c329489adc3801635350450465312e362e30a50666534841323536025820087d13c68f32aaafb8c4fc0a2253445432009765e216fb85c398c9580522c1bf055820b360caf5c98c6b942a4882fa9d4823efb166a9ef6a6e4aa37c1919ed1fccc04901644e5350450465302e302e30190960777777772e747275737465646669726d776172652e6f7267',
  h'304502210086e90f5aa170964d2ae6de6d0018e2e5609bf5c2d601289d4e314b930f700ff00220704e74aebea7de2b47b571acff334bb6252a9cb201120ec7478b7d0ef1c4fa1c'
])
~~~~~~~~~~~~~~~~~

which has the following base16 encoding:

~~~~~~~~~~~~~~~~~
d28443a10126a0590172aa19095d5820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0a481385b9708109c7fb19095a190bba19095e73303630343536353237323832392d313030313019095c5819aaaaaaaaabbbbbbbbbbbbbccccccccccccccdddddddddddddd190100582101fa58755f658627ce5460f29b75296713248cae7ad9e2984b90280efcbcb50248190109184219095b19300019095f82a50666534841323536025820e33ea1e002d2fe794d1a1679db58bb6a23a8f659bb77f89c458cecf9d5995ffd055820bfe6d86f8826f4ff97fb96c4e6fbc4993e4619fc565da26adf34c329489adc3801635350450465312e362e30a50666534841323536025820087d13c68f32aaafb8c4fc0a2253445432009765e216fb85c398c9580522c1bf055820b360caf5c98c6b942a4882fa9d4823efb166a9ef6a6e4aa37c1919ed1fccc04901644e5350450465302e302e30190960777777772e747275737465646669726d776172652e6f72675847304502210086e90f5aa170964d2ae6de6d0018e2e5609bf5c2d601289d4e314b930f700ff00220704e74aebea7de2b47b571acff334bb6252a9cb201120ec7478b7d0ef1c4fa1c
~~~~~~~~~~~~~~~~~

The Relying Party (co-located with the gateway) then treats the Evidence as opaque and sends it to the Verifier.
Once the Verifier sends back the Attestation Result, the Relying Party can be assured on the version of the firmware that the device is running.

# Open discussion: remote attestation over EDHOC/ over OSCORE

TBD

# Acknowledgments
{:numbered="false"}

The author would like to thank Thomas Fossati, Goran Selander, Malisa Vucinic, Ionut Mihalcea, Muhammad Usama Sardar and Michael Richardson for the provided feedback.
