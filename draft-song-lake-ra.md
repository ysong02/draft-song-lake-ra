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
    RFC8949:
    RFC8392:
    IANA.CWT.Claims: IANA.cwt
    I-D.tschofenig-rats-psa-token:
    IANA-CoAP-Content-Formats:
      title: CoAP Content-Formats
      target: https://www.iana.org/assignments/core-parameters

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

<!--Discuss the background check model and say that this specification supports the background check model.-->
One type of interaction model defined in the RATS architecture is called the background-check model.
It resembles the procedure of how employers perform background checks to determine the prospective employee's trustworthiness, by contacting the respective organization that issues a report.
In this case, the employer acts as the Relying Party, the employee acts as the Attester and the organization acts as the Verifier.
The Attester conveys evidence directly to the Relying Party and the Relying Party forwards the evidence to the Verifier for appraisal.
Once the attestation result is computed by the Verifier, it is sent back to the Relying Party to decide what action to take based on the attestation result.
This specification employs the RATS background check model.

<!--Discuss EAT-->
One way of conveying attestation evidence is the Entity Attestation Token (EAT) {{I-D.ietf-rats-eat}}.
It provides an attested claims set that describes the state and the characteristics of the Attester, which can be used to determine its level of trustworthiness.
This specification relies on the EAT as the attestation evidence.

<!--Summarize EDHOC {{I-D.ietf-lake-edhoc}}. Mention EAD fields of EDHOC.-->
Ephemeral Diffie-Hellman over COSE (EDHOC) {{I-D.ietf-lake-edhoc}} is a lightweight authenticated key exchange protocol for highly constrained networks.
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

The reader is assumed to be familiar with the terms and concepts defined in EDHOC {{I-D.ietf-lake-edhoc}} and RATS {{RFC9334}}.

# Problem Description

This specification describes how to perform remote attestation over the EDHOC protocol according to the RATS architecture.
Remote attestation protocol elements are carried within EDHOC's External Authorization Data (EAD) fields.
More specifically, this specification supports the RATS background check model.
It describes how the Attester (EDHOC Initiator) and Relying Party (EDHOC Responder) complete the EDHOC handshake complemented with remote attestation protocol elements.

# Assumptions

The details of the protocol between Relying Party and Verifier are out of the scope.
The only assumption is that the Verifier outputs a fresh nonce and that same nonce is passed on to the EDHOC session.
That is where the link between the two protocols comes in.
The remainder, such as the evidence type selection is just the negotiation.
In general, the Verifier is supposed to know how to verify more than one format of the evidence type.
Therefore, the Verifier MUST send back at least one format to the Relying Party.
We assume in this specification, the Relying Party also has knowledge about the Attester, so it can narrow down the type selection and send to the Attester only one format of evidnece type.


The Attester should have an explicit relation with the Verifier, such as from device manufacuture, so that the Verifier can evaluate the Evidence that is produced by the Attester.
The authentication between the Attester and the Relying Party is performed with EDHOC {{I-D.ietf-lake-edhoc}} and defines the process of remote attestation using the External Authorization Data (EAD) fields defined in EDHOC.

# The Protocol

## Overview

EDHOC Initiator plays the role of the RATS Attester.
EDHOC Responder plays the role of the RATS Relying Party.
An external entity, out of scope of this specification, plays the role of the RATS Verifier.


~~~~~~~~~~~ aasvg

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
|          |              |           |  Result       |          |
+----------+              +-----------+               +----------+

~~~~~~~~~~~
{: #fig-overview title="Overview of message flow. EDHOC is used between A and RP. Remote attestation proposal and request are sent in EDHOC External Authorization Data (EAD). The link between V and RP is out of scope of this specification." artwork-align="center"}


The Attester and the Relying Party communicate by transporting messages within EDHOC's External Authorization Data (EAD) fields.


## External Authorization Data 1 {#ead1}

In EAD_1, the Attester transports the Proposed_EvidenceType object.
It signals to the Relying Party the proposal to do remote attestation, as well as which attestation claims the Attester supports.
The supported attestation claims are encoded in CBOR in the form of a sequence.

The external authorization data EAD_1 contains an EAD item with

* ead_label = TBD1
* ead_value = Attestation_proposal, which is a CBOR byte string:

~~~~~~~~~~~~~~~~
Attestation_proposal = bstr .cbor Proposed_EvidenceType

Proposed_EvidenceType = (
	content-format: 	[ + uint]
)
~~~~~~~~~~~~~~~~

where

* content-format is an array that contains all the supported evidence types by the Attester in decreasing order of preference.
* There MUST be at least one item in the array.
* content-format is an indicator of the format type (e.g., application/eat+cwt with an appropriate eat_profile parameter set).

The sign of ead_label MUST be negative to indicate that the EAT item is critical.
If the receiver cannot recognize the critical EAD item, or cannot process the information in the critical EAD item, then the receiver MUST send an EDHOC error message back.


## External Authorization Data 2 {#ead2}

In EAD_2, the Relying Party signals to the Attester the supported and requested evidence types.
In case none of the evidence types is supported, the Relying Party rejects the first message_1 with an error indicating support for another evidence type.

EAD_2 carries the Selected_EvidenceType object.
Similarly to EAD_1, Selected_EvidenceType object is encoded in CBOR.

The external authorization data EAD_2 contains an EAD item with

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

## External Authorization Data 3 {#ead3}

As a response to the attestation request, the Attester calls its local attestation service to generate and return the serialized EAT {{I-D.ietf-rats-eat}} as Evidence.

The external authorization data EAD_3 contains an EAD item with

* ead_label = TBD3
* ead_value is a serialized EAT.

# Security Considerations

TODO: Security considerations


# IANA Considerations

## EDHOC External Authorization Data Registry

IANA is requested to register the following entry in the "EDHOC External Authorization Data" registry under the group name "Ephemeral Diffie-Hellman Over Cose (EDHOC)".
The ead_label = TBD1 corresponds to the ead_value Attestation_proposal in EAD_1 with processing specified in {{ead1}}.
The ead_label = TBD2 corresponds to the ead_value Attestation_request in {{ead2}}.
The ead_label = TBD3 corresponds to the ead_value which carries the EAT, as specified in {{ead3}}.

| Label | Value Type | Description |
| TBD1 | bstr | Attestation Proposal |
| TBD2 | bstr | Attestation Request |
| TBD3 | bstr | Evidence for remote attestation |
{: #ead-table title="Addition to the EDHOC EAD registry" cols="r l l"}

--- back

# Example: Remote Attestation Flow

~~~~aasvg
.--------------------------.
| Attestation   | Attester |         .---------------.     .----------.
| Service       |          |         | Relying Party |     | Verifier |
'--+----------------+------'         '-------+-------'     '-----+----'
   |                |                        |                   |
.--+------------.   |                        |                   |
| EDHOC session |   |                        |                   |
+--+------------+---+------------------------+-------------------+---.
|  |                |                        |                   |    |
|  |                |EDHOC message_1         |                   |    |
|  |                |  {...}                 |                   |    |
|  |                |  EAD_1(                |                   |    |
|  |                |    types(a,b,c)        |                   |    |
|  |                |  )                     |                   |    |
|  |                +----------------------->|                   |    |
|  |                |                        |                   |    |
|  |                |                        |                   |    |
|  |                |                        +------------------>|    |
|  |                |                        |                   |    |
|  |                |                        |                   |    |
|  |                |                        | Body: {           |    |
|  |                |                        |   nonce,          |    |
|  |                | EDHOC message_2        |   types(a,b)      |    |
|  |                |  {...}                 | }                 |    |
|  |                |  EAD_2(                |<------------------+    |
|  |                |    nonce,              |                   |    |
|  |                |    type(a)             |                   |    |
|  |                |  )                     |                   |    |
|  |                |  Auth_CRED(Sig/MAC)    |                   |    |
|  |                |<-----------------------+                   |    |
|  |   Body:{       |                        |                   |    |
|  |    nonce,      |                        |                   |    |
|  |    type(a)     |                        |                   |    |
|  |   }            |                        |                   |    |
|  |<---------------+                        |                   |    |
|  | Body:{         |                        |                   |    |
|  |   nonce,       |                        |                   |    |
|  |   Evidence     |                        |                   |    |
|  | }              |                        |                   |    |
|  +--------------->|                        |                   |    |
|  |                | EDHOC message_3        |                   |    |
|  |                |  {...}                 |                   |    |
|  |                |  EAT(nonce,Evidence)   |                   |    |
|  |                |  Auth_CRED(sig/MAC)    |                   |    |
|  |                +----------------------->|                   |    |
|  |                |                        |                   |    |
'--+----------------+------------------------+-------------------+----'
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
   |                |                        |                   |
   '----------------+------------------------+-------------------'
                    |    application data    |
                    |<---------------------->|
                    |                        |
~~~~
{: #figure-iot-example title="Example of remote attestation."

# Example: Firmware Version

The goal in this example is to verify that the firmware running on the device is the latest version, and is neither tampered or compromised.
A device acts as the Attester, currently in an untrusted state.
The Attester needs to generate the Evidence to attest itself.
A gateway that can communicate with the Attester and can control its access to the network acts as the Relying Party.
The gateway will finally decide whether the device can join the network or not depending on the Attestation Result.
The Attestation Result is produced by the Verifier, which is a web server that can be seen as the manufacturer of the device.
Therefore it can appraise the Evidence that is sent by the Attester.
The remote attestation session starts with the Attester sending EAD_1 in EDHOC message 1, as specified in {{ead1}}.
In EAD_1 field, the Attester indicates that the format of EAT is in CWT and the profile of EAT is Platform Security Architecture (PSA) attestation token {{I-D.tschofenig-rats-psa-token}}.
PSA attestation token contains the claims relating to the security state of the platform, which are provided by PSA's Initial Attestation API.

Therefore, the EAD_1 in EDHOC message_1 is:

~~~~~~~~~~~~~~~~
TBD
~~~~~~~~~~~~~~~~

According to {{I-D.tschofenig-rats-psa-token}}, IANA is requested to register the Content-Format ID in the "CoAP Content-Formats" registry {{IANA-CoAP-Content-Formats}}, for the `application/eat+cwt` media type with the `eat_profile` parameter equal to `tag:psacertified.org,2023:psa#tfm`.

The Media Type equivalent is:

~~~~~~~~~~~~~~~~
media-type: application/eat+cwt; eat_profile="tag:psacertified.org,2023:psa#tfm"
~~~~~~~~~~~~~~~~

If the Verifier and the Relying Party can support this evidence type that is proposed by the Attester, the Relying Party will include in the EAD_2 field the same evidence type, alongside a nonce for message freshness.

~~~~~~~~~~~~~~~~
TBD
~~~~~~~~~~~~~~~~

The Evidence in EAD_3 field is the Platform Security Architecture (PSA) attestation token, which is the attestation of the platform state to assure the firmware integrity.
This can be generated from Measured boot, which creates the measurements of loaded code and data during the boot process and make them part of an overall chain of trust.
Each stage of the chain of trust stores the measurements in a local root of trust, then the Root of Trust for Report (RTR) of the device can use them as materials to generate the Evidence.
The components of the Evidence should at least be:

~~~~~~~~~~~~~~~~
TBD
~~~~~~~~~~~~~~~~

The Relying Party (co-located with the gateway) then treats the Evidence as opaque and sends it to the Verifier.
Once the Verifier sends back the Attestation Result, the Relying Party can be assured on the version of the firmware that the device is running.

# Acknowledgments
{:numbered="false"}

The author would like to thank Thomas Fossati, Goran Selander, and Malisa Vucinic for the provided feedback.
