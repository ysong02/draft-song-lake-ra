---
title: "TODO - Your title"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-song-lake-ra-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Lightweight Authenticated Key Exchange"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Lightweight Authenticated Key Exchange"
  type: "Working Group"
  mail: "lake@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/lake/"
  github: "ysong02/RemoteAttestation_overEDHOC"
  latest: "https://ysong02.github.io/RemoteAttestation_overEDHOC/draft-song-lake-ra.html"

author:
 -
    fullname: "ysong02"
    organization: Your Organization Here
    email: "71662449+ysong02@users.noreply.github.com"

normative:

informative:


# abstract
Remote attesation is an essential process before the device can be admitted to join the network. The evidence that genereated from the device needs to be evaluated and verified to assure their integrity and trustworthiness. 
This document specifies the remote attestation process by which the evidence is conveyed during the handshake in EDHOC (Ephemeral Diffie-Hellman Over COSE, a very compact and lightweight key exchange protocol),
applied on the background-check model in RATS (Remote ATtestation ProcedureS) architecture. 



--- middle
# Table of Contents
1. [Introduction](#introduction)
3. [Conventions and Terminology](#conventions-and-terminology)
4. [Overview](#overview)
5. 

# Introduction
introduce EDHOC and RATS background-check model
## Handshake in Ephemeral Diffie-Hellman Over COSE (EDHOC)
## Background-check model in Remote ATtestation ProcedureS (RATS)


# Conventions and Terminology
The reader assumed to be familiar with the vocabulary and concepts defined in EDHOC[] and RATS[rfc]. 

Some words like evidence, credentials, ephemeral key, signature key...

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
RFC 2119 [RFC2119].

{::boilerplate bcp14-tagged}

# Overview
RATS has a background-check model.

EDHOC EAD.
# Remote attestation credentials in the EDHOC handshake
materials during the handshake

key exchange

nonce = EDHOC_ EXPORTER

EAD1 =

EAD2 = do remote attestation

EAD3 = EAT
# Evidence Extensions
structure of EAD
# EDHOC Initiator and Responder handshake behavior
the whole process of remote attestation (include the secure/non secure world? left-left and right-right part?)
# Examples
## Secure firmware management
# Security Considerations

TODO Security

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
