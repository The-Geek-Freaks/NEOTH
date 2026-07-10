---
title: "System Design 101 Reference"
description: "Konzepte, Protokolle und Architektur-Fallstudien für komplexe Systemdesigns"
tags: ["system-design", "architecture", "api", "database", "scaling", "case-studies"]
source: "sources/system_design_101_readme.md"
---

# [INTENT: SYSTEM_DESIGN_REFERENCE] System Design & Architektur-Wissen (Deep Dive Index)

## Chunk 1: API, Networking und Infrastruktur-Konzepte
Spezifische Architektur- und Netzwerk-Patterns für präzise RAG-Queries:
- **Netzwerk-Protokolle & Routing:** Unicast vs Broadcast vs Multicast vs Anycast, HTTP/1 -> HTTP/2 -> HTTP/3, SSE (Server-Sent Events) vs WebSocket vs Short/Long Polling. NAT (Network Address Translation), Internet Traffic Routing Policies, 18 Common Ports.
- **API Design & Gateways:** GraphQL Adoption Patterns, SOAP vs REST vs GraphQL vs RPC. Reverse Proxy vs API Gateway vs Load Balancer (inkl. Key Use Cases).
- **Security & Web Development:** 5 verbotene HTTP Status Codes, 12 Tipps für API Security, sicherer Web API Access, Pagination Patterns.

## Chunk 2: Real World Architecture Case Studies
Konkrete Skalierungs- und Architektur-Fälle von Tech-Giganten (als exakter Referenz-Index):
- **Databases & Storage:** Figma (100X Postgres Scaling), Discord (Speicherung von Billionen Nachrichten), S3 Large File Uploads.
- **Caching & Performance:** Netflix (4 Ways Netflix Uses Caching), Pinterest (Reduzierung der Clone-Zeiten um 99%).
- **Microservices & Event-Driven:** McDonald's Event-Driven Architecture, Airbnb (0 to 1.5 Billion Guests, Microservice Evolution), Netflix Overall Architecture & API Evolution.
- **Messaging & Feeds:** Slack Message Journey, Twitter 1.0 Tech Stack vs 2022, Twitter "For You" Recommendation (1.5 Sekunden Latenz), TikTok (200K File Frontend MonoRepo), YouTube (Massive Video Uploads).

## Chunk 3: Data Management & Storage Deep-Dive
Fortgeschrittene Datenhaltungsmuster und Storage-Algorithmen:
- **Storage-Techniken:** Erasure Coding, Time Series DB (TSDB) in 20 Lines.
- **Datenkonsistenz & Concurrency:** Pessimistic vs Optimistic Locking, Database Isolation Levels, Delivery Semantics (At-most-once, At-least-once, Exactly-once).
- **Messaging & Event-Sourcing:** The Ultimate Kafka 101, Kafka Message Loss Prevention, Kafka Speed Architecture. 4 Typen von Message Queues. Change Data Capture (CDC), Event Sourcing System Design, Read Replica Pattern, Avro Data Migration.
