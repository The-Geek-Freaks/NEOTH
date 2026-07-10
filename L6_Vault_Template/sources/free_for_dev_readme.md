Title: Live Content

Description: Fetched live

Source: https://raw.githubusercontent.com/ripienaar/free-for-dev/master/README.md

---

# free-for.dev

Developers and open-source authors now have many services offering free tiers, but finding them all takes time to make informed decisions.

This is a list of software (SaaS, PaaS, IaaS, etc.) and other offerings with free developer tiers.

The scope of this particular list is limited to things that infrastructure developers (System Administrators, DevOps Practitioners, etc.) are likely to find useful. We love all the free services out there, but it would be good to keep it on topic. It's a grey line sometimes, so this is opinionated; please don't feel offended if I don't accept your contribution.

This list results from Pull Requests, reviews, ideas, and work done by 1600+ people. You can also help by sending [Pull Requests](https://github.com/ripienaar/free-for-dev) to add more services or remove ones whose offerings have changed or been retired.

[![Track Awesome List](https://www.trackawesomelist.com/badge.svg)](https://www.trackawesomelist.com/ripienaar/free-for-dev)

**NOTE**: This list is only for as-a-Service offerings, not for self-hosted software. To be eligible, a service must offer a free tier, not just a free trial. The free tier must be for at least a year if it is time-bucketed. We also consider the free tier from a security perspective, so SSO is fine, but I will not accept services that restrict TLS to paid-only tiers.

# Table of Contents

  * [Major Cloud Providers' Always-Free Limits](#major-cloud-providers)
  * [Cloud management solutions](#cloud-management-solutions)
  * [Analytics, Events, and Statistics](#analytics-events-and-statistics)
  * [APIs, Data and ML](#apis-data-and-ml)
  * [Artifact Repos](#artifact-repos)
  * [BaaS](#baas)
  * [Low-code Platform](#low-code-platform)
  * [CDN and Protection](#cdn-and-protection)
  * [CI and CD](#ci-and-cd)
  * [CMS](#cms)
  * [Code Generation](#code-generation)
  * [Code Quality](#code-quality)
  * [Code Search and Browsing](#code-search-and-browsing)
  * [Crash and Exception Handling](#crash-and-exception-handling)
  * [Data Visualization on Maps](#data-visualization-on-maps)
  * [Managed Data Services](#managed-data-services)
  * [Design and UI](#design-and-ui)
  * [Dev Blogging Sites](#dev-blogging-sites)
  * [DNS](#dns)
  * [Docker Related](#docker-related)
  * [Domain](#domain)
  * [Education and Career Development](#education-and-career-development)
  * [Email](#email)
  * [Feature Toggles Management Platforms](#feature-toggles-management-platforms)
  * [Font](#font)
  * [Forms](#forms)
  * [Generative AI](#generative-ai)
  * [IaaS](#iaas)
  * [IDE and Code Editing](#ide-and-code-editing)
  * [International Mobile Number Verification API and SDK](#international-mobile-number-verification-api-and-sdk)
  * [Issue Tracking and Project Management](#issue-tracking-and-project-management)
  * [Log Management](#log-management)
  * [Mobile App Distribution and Feedback](#mobile-app-distribution-and-feedback)
  * [Management Systems](#management-system)
  * [Messaging and Streaming](#messaging-and-streaming)
  * [Miscellaneous](#miscellaneous)
  * [Monitoring](#monitoring)
  * [PaaS](#paas)
  * [Package Build System](#package-build-system)
  * [Payment and Billing Integration](#payment-and-billing-integration)
  * [Privacy Management](#privacy-management)
  * [Screenshot APIs](#screenshot-apis)
  * [Flutter Related and Building IOS Apps without Mac](#flutter-related-and-building-ios-apps-without-mac)
  * [Search](#search)
  * [Security and PKI](#security-and-pki)
  * [Authentication, Authorization, and User Management](#authentication-authorization-and-user-management)
  * [Source Code Repos](#source-code-repos)
  * [Storage and Media Processing](#storage-and-media-processing)
  * [Tunneling, WebRTC, Web Socket Servers and Other Routers](#tunneling-webrtc-web-socket-servers-and-other-routers)
  * [Testing](#testing)
  * [Tools for Teams and Collaboration](#tools-for-teams-and-collaboration)
  * [Translation Management](#translation-management)
  * [Visitor Session Recording](#visitor-session-recording)
  * [Web Hosting](#web-hosting)
  * [Commenting Platforms](#commenting-platforms)
  * [Browser based hardware emulation](#browser-based-hardware-emulation-written-in-javascript)
  * [Remote Desktop Tools](#remote-desktop-tools)
  * [Other Free Resources](#other-free-resources)

## Major Cloud Providers

  * [Google Cloud Platform](https://cloud.google.com)
    * App Engine - 28 frontend instance hours per day, nine backend instance hours per day
    * Cloud Firestore - 1GB storage, 50,000 reads, 20,000 writes, 20,000 deletes per day
    * Compute Engine - 1 non-preemptible e2-micro, 30GB HDD, 5GB snapshot storage (restricted to certain regions), 1 GB network egress from North America to all region destinations (excluding China and Australia) per month
    * Cloud Storage - 5GB, 1GB network egress
    * Cloud Shell - Web-based Linux shell/primary IDE with 5GB of persistent storage. 60-hour limit per week
    * Cloud Pub/Sub - 10GB of messages per month
    * Cloud Functions - 2 million invocations per month (includes both background and HTTP invocations)
    * Cloud Run - 2 million requests per month, 360,000 GB-seconds memory, 180,000 vCPU-seconds of compute time, 1 GB network egress from North America per month
    * Google Kubernetes Engine - No cluster management fee for one zonal cluster. Each user node is charged at standard Compute Engine pricing
    * BigQuery - 1 TB of querying per month, 10 GB of storage each month
    * Cloud Build - 120 build-minutes per day
    * [Google Colab](https://colab.research.google.com/) - Free Jupyter Notebooks development environment.
    * [Kaggle](https://www.kaggle.com/) - Jupyter Notebooks with 4 CPU cores and 30 GB RAM computational environment without any weekly usage limits. With Phone number verification, 1 Nvidia Tesla P100 GPU or 2x Nvidia Tesla T4 GPU can be added with a usage limit of 30 GPU hours/week for free. With Identity verification - 1 TPU v3-8 with 96 CPU cores and 330 GB RAM is available with a usage limit of 20 hours/week for free. Check [Technical Specifications](https://www.kaggle.com/docs/notebooks#technical-specifications) for more details.
    * [ChromeRemoteDesktop](https://remotedesktop.google.com/) - Free remote desktop app with practically no limit on the number of devices, owned by Google, so needs a Google account.
    * [Google Gemini API](https://ai.google.dev/) - Get free access to Gemini 1.5 Pro and Gemini 1.5 Flash models. The free tier offers 15 requests per minute, 1,500 requests per day, and 1 million tokens per minute.
    * Full, detailed list - https://cloud.google.com/free

  * [Amazon Web Services](https://aws.amazon.com)
    * [CloudFront](https://aws.amazon.com/cloudfront/) - 1TB egress per month and 2M Function invocations per month
    * [CloudWatch](https://aws.amazon.com/cloudwatch/) - 10 custom metrics and ten alarms
    * [CodeBuild](https://aws.amazon.com/codebuild/) - 100min of build time per month
    * [CodeCommit](https://aws.amazon.com/codecommit/) - 5 active users,50GB storage, and 10000 requests per month
    * [CodePipeline](https://aws.amazon.com/codepipeline/) - 1 active pipeline per month
    * [DynamoDB](https://aws.amazon.com/dynamodb/) - 25GB NoSQL DB
    * [EC2](https://aws.amazon.com/ec2/) - 750 hours per month of t2.micro or t3.micro(12mo). 100GB egress per month
    * [EBS](https://aws.amazon.com/ebs/) - 30GB per month of General Purpose (SSD) or Magnetic(12mo)
    * [Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/) - 750 hours per month(12mo)
    * [RDS](https://aws.amazon.com/rds/) - 750 hours per month of db.t2.micro, db.t3.micro, or db.t4g.micro, 20GB of General Purpose (SSD) storage, 20GB of storage backups(12 mo)
    * [S3](https://aws.amazon.com/s3/) - 5GB Standard object storage, 20K Get requests and 2K Put requests(12 mo)
    * [Glacier](https://aws.amazon.com/glacier/) - 10GB long-term object storage
    * [Lambda](https://aws.amazon.com/lambda/) - 1 million requests per month
    * [SNS](https://aws.amazon.com/sns/) - 1 million publishes per month
    * [SES](https://aws.amazon.com/ses/) - 3.000 messages per month (12mo)
    * [SQS](https://aws.amazon.com/sqs/) - 1 million messaging queue requests
    * Full, detailed list - https://aws.amazon.com/free/

  * [Microsoft Azure](https://azure.microsoft.com)
    * [Virtual Machines](https://azure.microsoft.com/services/virtual-machines/) - 1 B1S Linux VM, 1 B1S Windows VM (12mo)
    * [App Service](https://azure.microsoft.com/services/app-service/) - 10 web, mobile, or API apps (60 CPU minutes/day)
    * [Functions](https://azure.microsoft.com/services/functions/) - 1 million requests per month
    * [DevTest Labs](https://azure.microsoft.com/services/devtest-lab/) - Enable fast, easy, and lean dev-test environments
    * [Active Directory](https://azure.microsoft.com/services/active-directory/) - 500,000 objects
    * [Active Directory B2C](https://azure.microsoft.com/services/active-directory/external-identities/b2c/) - 50,000 monthly stored users
    * [Azure DevOps](https://azure.microsoft.com/services/devops/) - 5 active users, unlimited private Git repos
    * [Azure Pipelines](https://azure.microsoft.com/services/devops/pipelines/) - 10 free parallel jobs with unlimited minutes for open source for Linux, macOS, and Windows
    * [Microsoft IoT Hub](https://azure.microsoft.com/services/iot-hub/) - 8,000 messages per day
    * [Load Balancer](https://azure.microsoft.com/services/load-balancer/) - 1 free public load-balanced IP (VIP)
    * [Notification Hubs](https://azure.microsoft.com/services/notification-hubs/) - 1 million push notifications
    * [Bandwidth](https://azure.microsoft.com/pricing/details/bandwidth/) - 15GB Inbound(12mo) & 5GB egress per month
    * [Cosmos DB](https://azure.microsoft.com/services/cosmos-db/) - 25GB storage and 1000 RUs of provisioned throughput
    * [Static Web Apps](https://azure.microsoft.com/pricing/details/app-service/static/) - Build, deploy, and host static apps and serverless functions with free SSL, Authentication/Authorization, and custom domains
    * [Storage](https://azure.microsoft.com/services/storage/) - 5GB LRS File or Blob storage (12mo)
    * [Cognitive Services](https://azure.microsoft.com/services/cognitive-services/) - AI/ML APIs (Computer Vision, Translator, Face detection, Bots, etc) with free tier including limited transactions
    * [Cognitive Search](https://azure.microsoft.com/services/search/#features) - AI-based search and indexation service, free for 10,000 documents
    * [Azure Kubernetes Service](https://azure.microsoft.com/services/kubernetes-service/) - Managed Kubernetes service, free cluster management
    * [Event Grid](https://azure.microsoft.com/services/event-grid/) - 100K ops/month
    * Full, detailed list - https://azure.microsoft.com/free/

  * [Oracle Cloud](https://www.oracle.com/cloud/)
    * Compute
       - 2 AMD-based Compute VMs with 1/8 OCPU and 1 GB memory each
       - 2 Arm-based Ampere A1 cores and 12 GB of memory usable as one VM or up to 2 VMs
       - Instances will be reclaimed when [deemed idle](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm#compute__idleinstances)
    * Block Volume - 2 volumes, 200 GB total (used for compute)
    * Object Storage - 10 GB
    * Load balancer - 1 instance with 10 Mbps
    * Databases - 2 DBs, 20 GB each
    * Monitoring - 500 million ingestion data points, 1 billion retrieval datapoints
    * Bandwidth - 10 TB egress per month, speed limited to 50 Mbps on x64-based VM, 500 Mbps * core count on ARM-based VM
    * Public IP - 2 IPv4 for VMs, 1 IPv4 for load balancer
    * Notifications - 1 million delivery options per month, 1000 emails sent per month
    * Full, detailed list - https://www.oracle.com/cloud/free/

  * [IBM Cloud](https://www.ibm.com/cloud/free/)
    * Cloudant database - 1 GB of data storage
    * Db2 database - 100MB of data storage
    * API Connect - 50,000 API calls per month
    * Availability Monitoring - 3 million data points per month
    * Log Analysis - 500MB of daily log
    * Full, detailed list - https://www.ibm.com/cloud/free/

  * [Cloudflare](https://www.cloudflare.com/)
    * [Application Services](https://www.cloudflare.com/plans/) - Free DNS for an unlimited number of domains, DDoS Protection, CDN along with free SSL, Firewall rules and page rules,  WAF, Bot Mitigation, Free Unmetered Rate Limiting - 1 rule per domain, Analytics, Email forwarding
    * [Zero Trust & SASE](https://www.cloudflare.com/plans/zero-trust-services/) - Up to 50 Users, 24 hours of activity logging, three network locations
    * [Cloudflare Tunnel](https://www.cloudflare.com/products/tunnel/) -  You can expose locally running HTTP port over a tunnel to a random subdomain on trycloudflare.com use [Quick Tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/), No account required. More features (TCP tunnel, Load balancing, VPN) in [Zero Trust](https://www.cloudflare.com/products/zero-trust/) Free Plan.
    * [Workers](https://developers.cloudflare.com/workers/) - Deploy serverless code for free on Cloudflare's global network-100k daily requests.
    * [Workers KV](https://developers.cloudflare.com/kv) - 100k read requests per day, 1000 write requests per day, 1000 delete requests per day, 1000 list requests per day, 1 GB stored data
    * [R2](https://developers.cloudflare.com/r2/) - 10 GB per month, 1 million Class A operations per month, 10 million Class B operations per month
    * [D1](https://developers.cloudflare.com/d1/) - 5 million rows read per day, 100k rows written per day, 1 GB storage
    * [Pages](https://developers.cloudflare.com/pages/) - Develop and deploy your web apps on Cloudflare's fast, secure global network. Five hundred monthly builds, 100 custom domains, Integrated SSL, unlimited accessible seats, unlimited preview deployments, and full-stack capability via Cloudflare Workers integration.
    * [Queues](https://developers.cloudflare.com/queues/) - 1 million operations per month
    * [TURN](https://developers.cloudflare.com/calls/turn/) - 1TB of free (outgoing) traffic per month.

  * [Zoho](https://www.zoho.com) - Started as an e-mail provider but now provides a suite of services, some of which have free plans. List of services having free plans :
    * [Catalyst by Zoho](https://catalyst.zoho.com) -  PaaS/full-stack cloud platform with a generous [free tier](https://catalyst.zoho.com/free-tier.html)
    * [Zoho Apptics](https://www.zoho.com/apptics/) - Unified and actionable product analytics to monitor performance, analyze user behavior and collect feedback for mobile, web, and desktop apps with generous Free Forever plan.
    * [Email](https://zoho.com/mail) Free for 5 users. 5GB/user & 25 MB attachment limit, one domain.
    * [Zoho Assist](https://www.zoho.com/assist) - Zoho Assist's forever free plan includes one concurrent remote support license and Access to 5 unattended computer licenses for unlimited duration available for both professional and personnel use.
    * [Sprints](https://zoho.com/sprints) Free for 5 users,5 Projects & 500MB storage.
    * [Docs](https://zoho.com/docs) - Free for 5 users with 1 GB upload limit & 5GB storage. Zoho Office Suite (Writer, Sheets & Show) comes bundled.
    * [Projects](https://zoho.com/projects) - Free for 3 users, 2 projects & 10 MB attachment limit. The same plan applies to [Bugtracker](https://zoho.com/bugtracker).
    * [Connect](https://zoho.com/connect) - Team Collaboration free for 25 users with three groups, three custom apps, 3 Boards, 3 Manuals, and 10 Integrations along with channels, events & forums.
    * [Meeting](https://zoho.com/meeting) - Meetings with upto 3 meeting participants & 10 Webinar attendees.
    * [Vault](https://zoho.com/vault) - Password Management is accessible for Individuals.
    * [Showtime](https://zoho.com/showtime) - Yet another Meeting software for training for a remote session of up to 5 attendees.
    * [Notebook](https://zoho.com/notebook) - A free alternative to Evernote.
    * [Wiki](https://zoho.com/wiki) - Free for three users with 50 MB storage, unlimited pages, zip backups, RSS & Atom feed, access controls & customizable CSS.
    * [Subscriptions](https://zoho.com/subscriptions) - Recurring Billing management free for 20 customers/subscriptions & 1 user with all the payment hosting done by Zoho. The last 40 subscription metrics are stored
    * [Checkout](https://zoho.com/checkout) - Product Billing management with 3 pages & up to 50 payments.
    * [Desk](https://zoho.com/desk) - Customer Support management with three agents, private knowledge base, and email tickets. Integrates with [Assist](https://zoho.com/assist) for one remote technician & 5 unattended computers.
    * [Cliq](https://zoho.com/cliq) - Team chat software with 100 GB storage, unlimited users, 100 users per channel & SSO.
    * [Campaigns](https://zoho.com/campaigns) - Email Marketing
    * [Forms](https://zoho.com/forms) - Form Creator
    * [Sign](https://zoho.com/sign) - Paperless Signatures
    * [Surveys](https://zoho.com/surveys) - Online Surveys
     * [Bookings](https://zoho.com/bookings) - Appointment Scheduling

**[⬆️ Back to Top](#table-of-contents)**

## Cloud management solutions

  * [Brainboard](https://www.brainboard.co) - Collaborative solution to visually build and manage cloud infrastructures from end-to-end.
  * [Cloud 66](https://www.cloud66.com/) - Free for personal projects (includes one deployment server, one static site), Cloud 66 gives you everything you need to build, deploy, and grow your applications on any cloud without the headache of the “server stuff.”.
  * [deployment.io](https://deployment.io) - Deployment.io helps developers automate deployments on AWS. On our free tier, a developer (single user) can deploy unlimited static sites, web services, and environments. We provide 10 job executions free per month with previews and auto-deploys included in the free tier.
  * [Pulumi](https://www.pulumi.com/) - Modern infrastructure as a code platform that allows you to use familiar programming languages and tools to build, deploy, and manage cloud infrastructure.
  * [scalr.com](https://scalr.com/) - Scalr is a Terraform Automation and COllaboration (TACO) product used to better collaboration and automation on infrastructure and configurations managed by Terraform. Full Terraform CLI support, OPA integration, and a hierarchical configuration model. No SSO tax. All features are included. Use up to 50 runs/month for free.

**[⬆️ Back to Top](#table-of-contents)**

## Source Code Repos

  * [Bitbucket](https://bitbucket.org/) - Unlimited public and private Git repos for up to 5 users with Pipelines for CI/CD
  * [Codeberg](https://codeberg.org/) - Unlimited public and private Git repos for free and open-source projects (with unlimited collaborators). Powered by [Forgejo](https://forgejo.org/). Static website hosting with [Codeberg Pages](https://codeberg.page/). CI/CD hosting with [Codeberg's CI](https://docs.codeberg.org/ci/). Translating hosting with [Codeberg Translate](https://translate.codeberg.org/). Includes Package and Container hosting, Project management, and Issue Tracking
  * [framagit.org](https://framagit.org/) - Framagit is the software forge of Framasoft based on the Gitlab software includes CI, Static Pages, Project pages and Issue tracking.
  * [GitGud](https://gitgud.io) - Unlimited private and public repositories. Free forever. Powered by GitLab & Sapphire. Includes CI/CD, Static Hosting, Container Registry, Project Management and Issue Tracking.
  * [GitHub](https://github.com/) - Unlimited public repositories and unlimited private repositories (with unlimited collaborators). Includes CI/CD, Development Environment, Static Hosting, Package and Container hosting, Project management and AI Copilot
  * [gitlab.com](https://about.gitlab.com/) - Unlimited public and private Git repos with up to 5 collaborators. Includes CI/CD, Static Hosting, Container Registry, Project Management and Issue Tracking
  * [heptapod.net](https://foss.heptapod.net/) - Heptapod is a friendly fork of GitLab Community Edition providing support for Mercurial
  * [pijul.com](https://pijul.com/) - Unlimited free and open source distributed version control system. Its distinctive feature is based on a sound theory of patches, which makes it easy to learn, use, and distribute. Solves many problems of git/hg/svn/darcs.
  * [projectlocker.com](https://projectlocker.com) - One free private project (Git and Subversion) with 50 MB of space
  * [RocketGit](https://rocketgit.com) - Repository Hosting based on Git. Unlimited Public and private repositories.
  * [savannah.gnu.org](https://savannah.gnu.org/) - Serves as a collaborative software development management system for free Software projects (for GNU Projects)
  * [savannah.nongnu.org](https://savannah.nongnu.org/) - Serves as a collaborative software development management system for free Software projects (for non-GNU projects)

**[⬆️ Back to Top](#table-of-contents)**

## APIs, Data, and ML

  * [Abstract API](https://www.abstractapi.com) - API suite for various use cases, including IP geolocation, phone number validation, or email validation.
  * [AlphaAI](https://alphai.io/developers) - Financial news API and MCP server. Every article gets per-ticker impact analysis, a category, and a 1-10 relevance score, and SEC Form 4 insider filings are turned into scored events. The free tier includes 20 requests per minute and 100 requests per day on both REST and MCP, no card required.
  * [Apify](https://www.apify.com/) - Web scraping and automation platform to create an API for any website and extract data. Ready-made scrapers, integrated proxies, and custom solutions. Free plan with $5 platform credits included every month.
  * [APITemplate.io](https://apitemplate.io) - Auto-generate images and PDF documents with a simple API or automation tools like Zapier & Airtable. No CSS/HTML is required. The free plan comes with 50 images/month and three templates.
  * [APIVerve](https://apiverve.com) - Get instant access to over 120+ APIs for free, built with quality, consistency, and reliability in mind. The free plan covers up to 50 API Tokens per month. (Possibly taken down, 2025-06-25)
  * [Arize AI](https://arize.com/) - Machine learning observability for model monitoring and root-causing issues such as data quality and performance drift. Free up to two models.
  * [Beeceptor](https://beeceptor.com) - No-code, cloud-based platform for mocking and debugging multi-protocol APIs (REST, SOAP, gRPC & GraphQL), providing instant servers with rules-based logic, CRUD & stateful mocking, proxying, and CORS management for faster integration and testing. The free plan includes 50 requests per day and provides a public dashboard/endpoint where anyone with the dashboard URL can view submitted requests and responses.
  * [BigDataCloud](https://www.bigdatacloud.com/) - Provides fast, accurate, and free (Unlimited or up to 10K-50K/month) APIs for modern web like IP Geolocation, Reverse Geocoding, Networking Insights, Email and Phone Validation, Client Info and more.
  * [Brave Search API](https://brave.com/search/api/) - Independent web, news, image, video search and AI/LLM context API, suitable for RAG pipelines and AI agents. Free tier includes $5 in monthly credits (credit card required for verification).
  * [Browse AI](https://www.browse.ai) - Extracting and monitoring data on the web. 1k credits per month for free, equals 1k concurrent requests.
  * [BrowserCat](https://www.browsercat.com) - Headless browser API for automation, scraping, AI agent web access, image/pdf generation, and more. Free plan with 1k requests per month.
  * [Calendarific](https://calendarific.com) - Enterprise-grade Public holiday API service for over 200 countries. The free plan includes 500 calls per month.
  * [Canopy](https://www.canopyapi.co/) - GraphQL API for Amazon.com product, search, and category data. The free plan includes 100 calls per month.
  * [CarAPI.dev](https://carapi.dev) - Comprehensive automotive data API with VIN decoding, stolen vehicle checks, vehicle valuation, inspection data, and more. Free tier includes 100 requests/month across all 9 endpoints.
  * [CatchDoms](https://catchdoms.com) - Aggregator of expired and dropping domain listings from 16 marketplaces, with SEO enrichment (backlinks, Trust Flow, Wayback history) and a quality score. Free plan: 10 unlocked listings, 5 favorites, 3 saved searches. 7-day Pro trial on signup includes full REST API and MCP server access.
  * [Cloudmersive](https://cloudmersive.com/) - Utility API platform with full access to expansive API Library including Document Conversion, Virus Scanning, and more with 600 calls/month, North America AZ only, 2.5MB maximum file size.
  * [Colaboratory](https://colab.research.google.com) - Free web-based Python notebook environment with Nvidia Tesla K80 GPU.
  * [CometML](https://www.comet.com/site/) - The MLOps platform for experiment tracking, model production management, model registry, and complete data lineage, covering your workflow from training to production. Free for individuals and academics.
  * [Commerce Layer](https://commercelayer.io) - Composable commerce API that can build, place, and manage orders from any front end. The developer plan allows 100 orders per month and up to 1,000 SKUs for free.
  * [Composio](https://composio.dev/) - Integration platform for AI Agents and LLMs. Integrate over 200+ tools across the agentic internet.
  * [Conversion Tools](https://conversiontools.io/) - Online File Converter for documents, images, video, audio, and eBooks. REST API is available. Libraries for Node.js, PHP, Python. Support files up to 50 GB (for paid plans). The free tier is limited by file size (20MB) and number of conversions (30/Day, 300/Month).
  * [Country-State-City Microservice API](https://country-state-city.rebuscando.info/) - API and Microservice to provides a wide range of information including countries, regions, provinces, cities, postal codes, and much more. The free tier includes up to 100 requests per day.
  * [Coupler](https://www.coupler.io/) - Data integration tool that syncs between apps. It can create live dashboards and reports, transform and manipulate values, and collect and back up insights. The free plan is limited to one user, data connection, data source, and data destination. Also requires manual data refresh.
  * [CraftMyPDF](https://craftmypdf.com) - Auto-Generate PDF documents from reusable templates with a drop-and-drop editor and a simple API. The free plan comes with 100 PDFs/month and three templates.
  * [Cube](https://cube.dev/) - Cube helps data engineers and application developers access data from modern data stores, organize it into consistent definitions, and deliver it to every application. The fastest way to use Cube is with Cube Cloud, which has a free tier limited to 1,000 queries per day.
  * [CurlHub](https://curlhub.io) - Proxy service for inspecting and debugging API calls. The free plan includes 10,000 requests per month.
  * [CurrencyScoop](https://currencyscoop.com) - Realtime currency data API for fintech apps. The free plan includes 5,000 calls per month.
  * [CustomJS](https://www.customjs.io) - HTML to PDF or PDF to PNG/Text & PDF merging/extraction/merging APIs. Free tier has 600 calls a month.
  * [Data Fetcher](https://datafetcher.com) - Connect Airtable to any application or API with no code. Postman-like interface for running API requests in Airtable. Pre-built integrations with dozens of apps. The free plan includes 100 runs per month.
  * [Data Miner](https://dataminer.io/) - A browser extension (Google Chrome, MS Edge) for data extraction from web pages CSV or Excel. The free plan gives you 500 pages/month.
  * [Dataimporter.io](https://www.dataimporter.io) - Tool for connecting, cleaning, and importing data into Salesforce. Free Plan includes up to 20,000 records per month.
  * [Datalore](https://datalore.jetbrains.com) - Python notebooks by Jetbrains. Includes 10 GB of storage and 120 hours of runtime each month.
  * [DB Designer](https://www.dbdesigner.net/) - Cloud-based Database schema design and modeling tool with a free starter plan of 2 Database models and ten tables per model.
  * [DB-IP](https://db-ip.com/api/free) - Free IP geolocation API with 1k request per IP per day.lite database under the CC-BY 4.0 License is free too.
  * [DeepAR](https://developer.deepar.ai) - Augmented reality face filters for any platform with one SDK. The free plan provides up to 10 monthly active users (MAU) and tracks up to 4 faces
  * [Deepnote](https://deepnote.com) - A new data science notebook. Jupyter is compatible with real-time collaboration and running in the cloud. The free tier includes unlimited personal projects, unlimited basic machines with 5GB RAM and 2vCPU, and teams with up to 3 editors.
  * [Compare JSON](https://comparejson.com) - An online tool for comparing differences between two JSON data structures, helping you quickly locate the differences in JSON data.
  * [Disease.sh](https://disease.sh/) - A free API providing accurate data for building the Covid-19 related useful Apps.
  * [Doczilla](https://www.doczilla.app/) - SaaS API empowering the generation of screenshots or PDFs directly from HTML/CSS/JS code. The free plan allows 250 documents month.
  * [Doppio](https://doppio.sh/) - Managed API to generate and privately store PDFs and Screenshots using top rendering technology. The free plan allows 400 PDFs and Screenshots per month.
  * [Doqlo](https://doqlo.com/) - Bulk fill and mail merge PDF forms from CSV using the web app or Public API. The free plan includes 100 output PDFs/month.
  * [drawDB](https://drawdb.app/) - Free and open-source online database diagram editor with no signup required.
  * [DynamicDocs](https://advicement.io) - Generate PDF documents with JSON to PDF API based on LaTeX templates. The free plan allows 50 API calls per month and access to a library of templates.
  * [Earnings Feed](https://earningsfeed.com/api) - Real-time SEC filings, insider trades, and institutional holdings API. Free tier includes 15 requests per minute.
  * [Export SDK](https://exportsdk.com) - PDF generator API with drag-and-drop template editor that provides an SDK and no-code integrations. The free plan has 250 monthly pages, unlimited users, and three templates.
  * [ExtendsClass](https://extendsclass.com/rest-client-online.html) - Free web-based HTTP client to send HTTP requests.
  * [Financial Data](https://financialdata.net/) - Stock market and financial data API. Free plan allows 300 requests per day.
  * [Firecrawl](https://www.firecrawl.dev/) - API that crawls websites and converts them into clean, LLM-ready markdown or structured data, handling JavaScript rendering, proxies, and rate limits. The free plan includes 1,000 credits per month with no credit card required.
  * [FormatJSONOnline.com](https://formatjsononline.com) - A free, browser-based tool to format, validate,compare and minify JSON data instantly.
  * [FraudLabs Pro](https://www.fraudlabspro.com) - Screen an order transaction for credit card payment fraud. This REST API will detect all possible fraud traits based on the input parameters of an order. The Free Micro plan has 500 transactions per month.
  * [FreeIPAPI](https://freeipapi.com) - Free, Fast and Reliable IP Geolocation API for commercial and non-commercial users available in JSON
  * [Geolocated.io](https://geolocated.io) - IP Geolocation API with multi-continent servers, offering a free plan with 2,000 requests per day.
  * [Hex](https://hex.tech/) - a collaborative data platform for notebooks, data apps, and knowledge libraries. Free community tier with up to five projects.
  * [Hook0](https://www.hook0.com/) - Hook0 is an open-source Webhooks-as-a-service (WaaS) that makes it easy for online products to provide webhooks. Dispatch up to 100 events/day with seven days of history retention for free.
  * [Hoppscotch](https://hoppscotch.io) - A free, fast, and beautiful API request builder.
  * [HS Ping](https://hsping.com) - A multi-country HS (Harmonized System) and HTS (Harmonized Tariff System) code lookup API, with a free plan offering 100 lookups/day.
  * [huggingface.co](https://huggingface.co) - Build, train, and deploy NLP models for Pytorch, TensorFlow, and JAX. Free up to 30k input characters/mo.
  * [Insomnia](https://insomnia.rest) - Open-source API client for designing and testing APIs, it supports REST and GraphQL
  * [Invantive Cloud](https://cloud.invantive.com/) - Access over 70 (cloud)platforms such as Exact Online, Twinfield, ActiveCampaign or Visma using Invantive SQL or OData4 (typically Power BI or Power Query). Includes data replication and exchange. Free plan for developers and implementation consultants. Free for specific platforms with limitations in data volumes.
  * [IP Geolocation API by ipwho.org](https://ipwho.org/) - 2,000 free requests per day. Fast, enterprise grade API at non-enterprise prices. Trusted by developers, corporate, government and education clients. Servers in 12+ regions.
  * [IP Geolocation API](https://www.abstractapi.com/ip-geolocation-api) - IP Geolocation API from Abstract - Allows 1,000 free requests.
  * [IP Geolocation](https://ipgeolocation.io/) - IP Geolocation API - Forever free plan for developers with a 1,000 requests per day limit.
  * [ip-api](https://ip-api.com) - IP Geolocation API, Free for non-commercial use, no API key required, limited to 45 req/minute from the same IP address for the free plan.
  * [IP.City](https://ip.city) - 100 Free IP geolocation requests per day
  * [IP2Location.io](https://www.ip2location.io/) - Freemium, fast, and reliable IP geolocation API. Get data like city, coordinates, ISP, ASN, AS data and more. The free plan includes 50k credits per month. IP2Location.io also offers 500 free WHOIS and hosted domain lookups per month. See domain registration details and find domains hosted on a specific IP. Upgrade to a paid plan for more features.
  * [Proxmint GeoIP](https://proxmint.com/tools/ip-lookup) — Free IP → country/city/ASN JSON API, no key, CORS-open. MaxMind GeoLite2.
  * [ip2geo.dev](https://ip2geo.dev) - IP geolocation API to convert IP addresses into location data including city, country, timezone, ASN, and currency. The free plan includes 1,000 requests per month.
  * [ipaddress.sh](https://ipaddress.sh) - Simple service to get a public IP address in different [formats](https://about.ipaddress.sh/).
  * [ipapi.is](https://ipapi.is/) - A reliable IP Address API from Developers for Developers with the best Hosting Detection capabilities that exist. The free plan offers 1000 lookups without signup.
  * [ipapi](https://ipapi.co/) - IP Address Location API by Kloudend, Inc - A reliable geolocation API built on AWS, trusted by Fortune 500. The free tier offers 30k lookups/month (1k/day) without signup.
  * [ipbase.com](https://ipbase.com) - IP Geolocation API - Forever free plan that spans 150 monthly requests.
  * [IPinfo](https://ipinfo.io/) - Fast, accurate, and free (up to 50k/month) IP address data API. Offers APIs with details on geolocation, companies, carriers, IP ranges, domains, abuse contacts, and more. All paid APIs can be trialed for free.
  * [IPLocate](https://www.iplocate.io) - IP Geolocation API, free up to 1,000 requests/day. Includes proxy/VPN/hosting detection, ASN data, IP to Company, and more. IPLocate also offers free downloadable IP to Country and IP to ASN databases in CSV or GeoIP-compatible MMDB formats.
  * [IPTrace](https://iptrace.io) - An embarrassingly simple API that provides your business with reliable and helpful IP geolocation data with 50,000 free lookups per month.
  * [JSON IP](https://getjsonip.com) - Returns the Public IP address of the client it is requested from. No registration is required for the free tier. Using CORS, data can be requested using client-side JS directly from the browser. Useful for services monitoring change in client and server IPs. Unlimited Requests.
  * [JSON to Table](https://jsontotable.org) - Convert JSON into an interactive table for quick viewing, editing, and sharing online.
  * [JSON2Video](https://json2video.com) - A video editing API to automate video marketing and social media videos, programmatically or with no code.
  * [JSONGrid](https://jsongrid.com) - Free tool to Visualize, Edit, Filter complex JSON data into beautiful tabular Grid. Save and Share JSON data over link link.
  * [JSONing](https://jsoning.com/api/) - Create a fake REST API from a JSON object, and customize HTTP status codes, headers, and response bodies.
  * [JSONSwiss](https://www.jsonswiss.com/) - JSONSwiss is a powerful online JSON viewer, editor, and validator. Format, visualize, search, and manipulate JSON data with AI-powered repair, tree view, table view, code generation in 12+ programming languages, convert json to csv, xml, yaml, properties and more.
  * [KillBait API](https://killbait.com/api/doc) - KillBait API allows users to submit URLs for content evaluation, detecting potential clickbait and categorizing articles. The API is designed for moderate publishing frequency, with limits of 1 submission per hour and 10 per day. Media partners can request higher limits.
  * [Kreya](https://kreya.app) - Free gRPC GUI client to call and test gRPC APIs. Can import gRPC APIs via server reflection.
  * [LoginLlama](https://loginllama.app) - A login security API to detect fraudulent and suspicious logins and notify your customers. Free for 1,000 logins per month.
  * [Market Data API](https://www.marketdata.app) - Provides real-time and historical financial data for stocks, options, mutual funds, and more. The Free Forever API tier allows for 100 daily API requests at no charge.
  * [Maxim AI](https://getmaxim.ai/) - Simulate, evaluate, and observe your AI agents. Maxim is an end-to-end evaluation and observability platform, helping teams ship their AI agents reliably and >5x faster. Free forever for indie developers and small teams (3 seats).
  * [microlink.io](https://microlink.io/) - It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities, or screenshots as a service. 50 requests per day, every day free.
  * [Mintlify](https://mintlify.com) - Modern standard for API documentation. Beautiful and easy-to-maintain UI components, in-app search, and interactive playground. Free for 1 editor.
  * [MockAPI](https://www.mockapi.io/) - MockAPI is a simple tool that lets you quickly mock up APIs, generate custom data, and perform operations using a RESTful interface. MockAPI is meant to be a prototyping/testing/learning tool. One project/2 resources per project for free.
  * [Mockerito](https://mockerito.com/) - Free mock REST API service providing realistic data across 9 domains (e-commerce, finance, healthcare, education, recruitment, social media, stock markets, weather, and aviation). No mandatory signup, no API keys, unlimited requests. Perfect for frontend prototyping, API testing, learning and teaching web development.
  * [Mockfly](https://www.mockfly.dev/) - Mockfly is a trusted development tool for API mocking and feature flag management. Quickly generate and control mock APIs with an intuitive interface. The free tier offers 500 requests per day.
  * [Mocko.dev](https://mocko.dev/) - Proxy your API, choose which endpoints to mock in the cloud and inspect traffic, for free. Speed up your development and integration tests.
  * [Multi-Exit IP Address Checker](https://ip.alstra.ca/) -  A free and simple tool to check your exit IP address across multiple nodes and understand how your IP appears to different global regions and services. Useful for testing rule-based DNS splitting tools such as Control D.
  * [News API](https://newsapi.org) - Search news on the web with code, and get JSON results. Developers get 100 queries free each day. Articles have a 24 hour delay.
  * [numlookupapi.com](https://numlookupapi.com) - Free phone number validation API - 100 free requests / month.
  * [OCR.Space](https://ocr.space/) - An OCR API parses image and pdf files that return the text results in JSON format. 25,000 requests per month are free and a 1MB file size limit.
  * [OpenAPI3 Designer](https://openapidesigner.com/) - Visually create Open API 3 definitions for free.
  * [Parseur](https://parseur.com) - 20 free pages/month: Extract data from PDFs, emails. AI powered. Full API access.
  * [PDF-API.io](https://pdf-api.io) - PDF Automation API, visual template editor or HTML to PDF, dynamic data integration, and PDF rendering with an API. The free plan comes with one template, 100 PDFs/month.
  * [PDFBolt](https://pdfbolt.com) - Developer-focused PDF generation API designed with privacy in mind. It offers Stripe-inspired documentation and includes 500 free PDF conversions per month.
  * [Pixela](https://pixe.la/) - Free daystream database service. All operations are performed by API. Visualization with heat maps and line graphs is also possible.
  * [Posthook](https://posthook.io) - Schedule webhooks to fire at a future time with automatic retries, delivery tracking, and failure alerting. Free plan includes 1,000 webhooks per month.
  * [Postman](https://postman.com) - Simplify workflows and create better APIs - faster - with Postman, a collaboration platform for API development. Use the Postman App for free forever. Postman cloud features are also free forever with certain limits.
  * [PrefectCloud](https://www.prefect.io/cloud/) - A complete platform for dataflow automation. Free plan includes 5 deployed workflows and 500 minutes of serverless compute credits per month.
  * [Preset Cloud](https://preset.io/) - A hosted Apache Superset service. Forever free for teams of up to 5 users, featuring unlimited dashboards and charts, a no-code chart builder, and a collaborative SQL editor.
  * [ProxySentry](https://proxysentry.io/) - IP API that detects residential proxies and VPNs. ProxySentry.io offers a free tier with 10k requests per month on rapidapi.com.
  * [Reducto](https://reducto.ai) - Turn any unstructured documents (PDF, XLSX, JPG, PPTX, etc.) into structured JSON data. Parse, extract data, and edit PDF forms. Free tier with 15k free credits and pay-as-you-go.
  * [Rendi](https://rendi.dev) - FFmpeg API - A REST API for FFmpeg, run FFmpeg online without handling the infrastructure. Free tier with monthly processing quota and 4 vCPUs available.
  * [RequestBin.com](https://requestbin.com) - Create a free endpoint to which you can send HTTP requests. Any HTTP requests sent to that endpoint will be recorded with the associated payload and headers so you can observe recommendations from webhooks and other services.
  * [ROBOHASH](https://robohash.org/) - Web service to generate unique and cool images from any text.
  * [Scraper's Proxy](https://scrapersproxy.com) - Simple HTTP proxy API for scraping. Scrape anonymously without having to worry about restrictions, blocks, or captchas. First 100 successful scrapes per month free including javascript rendering (more available if you contact support).
  * [ScrapingAnt](https://scrapingant.com/) - Headless Chrome scraping API and free checked proxies service. Javascript rendering, premium rotating proxies, CAPTCHAs avoiding. Free 10,000 API credits.
  * [SerpApi](https://serpapi.com/) - Real-time search engine scraping API. Returns structured JSON results for Google, YouTube, Bing, Baidu, Walmart, and many other machines. The free plan includes 100 successful API calls per month.
  * [Sheetson](https://sheetson.com) - Instantly turn any Google Sheets into a RESTful API. Free plan available, including 1,000 free rows per sheet.
  * [SikkerAPI](https://sikkerapi.com) - Free IP Reputation & Threat Intelligence, powered by a globally distributed high interaction honeypot network and community reported abuse incidents. 1,000 free IP lookups, TAXII indicators & reports per day, pull 5,000 fresh IPs from our blacklists daily and monitor your own CIDR ranges (/16) free free.
  * [Simplescraper](https://simplescraper.io) - Trigger your webhook after each operation. The free plan includes 100 cloud scrape credits.
  * [Geekflare API](https://geekflare.com/api/) - Geekflare API lets you scrape websites into Markdown, take screenshots, perform TLS scans and DNS lookups, test load times, and more. The free plan offers 500 API credits per month (e.g., 500 DNS lookups, 250 web scrapes, or 100 screenshots). See [credit mapping](https://docs.geekflare.com/api/api-credit-mapping).
  * [SmartParse](https://smartparse.io) - SmartParse is a data migration and CSV to API platform that offers time- and cost-saving developer tools. The Free tier includes 300 Processing Units per month, Browser uploads, Data quarantining, Circuit breakers, and Job Alerts.
  * [Sofodata](https://www.sofodata.com/) - Create secure RESTful APIs from CSV files. Upload a CSV file and instantly access the data via its API allowing faster application development. The free plan includes 2 APIs and 2,500 API calls per month. You don't need a credit card.
  * [Sqlable](https://sqlable.com/) - A collection of free online SQL tools, including an SQL formatter and validator, SQL regex tester, fake data generator, and interactive database playgrounds.
  * [Svix](https://www.svix.com/) - Webhooks as a Service. Send up to 50,000 messages/month for free.
  * [Tavily AI](https://tavily.com/) - API for online search and rapid insights and comprehensive research, with the capability of organization of research results. 1000 request/month for the Free tier with No credit card required.
  * [TemplateFox](https://pdftemplateapi.com) - PDF generation API with a visual template editor, dynamic data merging, and SDKs for 7 languages. Free plan includes 60 PDFs/month and 3 templates.
  * [The IP API](https://theipapi.com/) - IP Geolocation API with 1000 free requests / day. Provides information about the location of an IP address, including country, city, region, and more.
  * [TinyMCE](https://www.tiny.cloud) - rich text editing API. Core features are free for unlimited usage.
  * [Tomorrow.io Weather API](https://www.tomorrow.io/weather-api/) - Offers free plan of weather API. Provides accurate and up-to-date weather forecasting with global coverage, historical data and weather monitoring solutions.
  * [Treblle](https://www.treblle.com) - Treblle helps teams build, ship, and govern APIs. With advanced API log aggregation, observability, docs, and debugging. You get all features for free, but there is a limit of up to 250k requests per month on the free tier.
  * [Trophy](https://trophy.so) - API infrastructure for building gamification features like achievements, streaks, points and leaderboards in web and mobile apps. Free for 100 monthly active users.
  * [UniRateAPI](https://unirateapi.com) - Real-time exchange rates for 590+ currencies and crypto. Unlimited API calls on the free plan, perfect for developers and finance apps.
  * [vatcheckapi.com](https://vatcheckapi.com) - Simple and free VAT number validation API. 150 free validations per month.
  * [vatnode](https://vatnode.dev) - EU VAT number validation REST API with VIES and national tax-registry fallback, returning the official VIES consultation number for audit records. Free tier of 100 validations/month, no credit card.
  * [WeatherXu](https://weatherxu.com/) - Global weather data including current conditions, hourly and daily forecasts, and weather alerts via our API. Integrating AI models and ML systems to analyze and combine multiple weather models to deliver improved forecast accuracy. Free tier includes 10,000 API calls/month.
  * [WebScraping.AI](https://webscraping.ai) - Simple Web Scraping API with built-in parsing, Chrome rendering, and proxies. Two thousand free API calls per month.
  * [Weights & Biases](https://wandb.ai) - The developer-first MLOps platform. Build better models faster with experiment tracking, dataset versioning, and model management. Free tier for personal projects only, with 100 GB of storage included.
  * [What Is My IP](https://whatismyip.help) - A free service to check your public IPv4 and IPv6 address and related request data through an API with different output formats for automation, scripts, and network troubleshooting.
  * [What The Diff](https://whatthediff.ai) - AI-powered code review assistant. The free plan has a limit of 25,000 monthly tokens (~10 PRs).
  * [wolfram.com](https://wolfram.com/language/) - Built-in knowledge-based algorithms in the cloud.
  * [wrapapi.com](https://wrapapi.com/) - Turn any website into a parameterized API. 30k API calls per month.
  * [Zenscrape](https://zenscrape.com/web-scraping-api) - Web scraping API with headless browsers, residentials IPs, and straightforward pricing. One thousand free API calls/month and extra credits for students and non-profits.
  * [Zipcodebase](https://zipcodebase.com) - Free Zip Code API, access to Worldwide Postal Code Data. 5,000 free requests/month.
  * [Zip-Codes](https://www.zip-codes.com/api/) - REST API for US and Canadian postal codes with address validation, radius search, and Census demographics. 2,500 free requests/day.
  * [Zipcodestack](https://zipcodestack.com) - Free Zip Code API and Postal Code Validation. Ten thousand free requests/month.
  * [Zuplo](https://zuplo.com/) - Free API Management platform to design, build, and deploy APIs to the Edge. Add API Key authentication, rate limiting, developer documentation and Monetization to any API in minutes. OpenAPI-native and fully-programmable with web standard apis & Typescript. The free plan offers up to 10 projects, unlimited production edge environments, 1M monthly requests, and 10GB egress.
  * [Metashot](https://metashot.io) — Open Graph (OG) social preview image generation API. Generate dynamic 1200×630 images for Twitter, LinkedIn and Facebook via URL params, edge-cached on Cloudflare Workers. Free tier: 1,000 renders/month. Paid plans from $12/month.

**[⬆️ Back to Top](#table-of-contents)**

## Artifact Repos

  * [Gemfury](https://gemfury.com) - Private and public artifact repos for Maven, PyPi, NPM, Go Module, Nuget, APT, and RPM repositories. Free for public projects.
  * [jitpack.io](https://jitpack.io/) - Maven repository for JVM and Android projects on GitHub, free for public projects.
  * [paperspace](https://www.paperspace.com/) - Build & scale AI models, Develop, train, and deploy AI applications, free plan: public projects, 5Gb storage, basic instances.
  * [RepoFlow](https://repoflow.io) - RepoFlow Simplifies package management with support for npm, PyPI, Docker, Go, Helm, and more. Try it for free with 10GB storage, 10GB bandwidth, 100 packages, and unlimited users in the cloud, or self-hosted for personal use only.
  * [RepoForge](https://repoforge.io) - Private cloud-hosted repository for Python, Debian, NPM packages and Docker registries. Free plan for open source/public projects.
  * [repsy.io](https://repsy.io) - 1 GB Free private/public Maven Repository.

**[⬆️ Back to Top](#table-of-contents)**

## Tools for Teams and Collaboration

  * [3Cols](https://3cols.com/) - A free cloud-based code snippet manager for personal and collaborative code.
  * [BookmarkOS.com](https://bookmarkos.com) - Free all-on-one bookmark manager, tab manager, and task manager in a customizable online desktop with folder collaboration.
  * [Braid](https://www.braidchat.com/) - Chat app designed for teams. Free for public access group, unlimited users, history, and integrations. also, it provides a self-hostable open-source version.
  * [Calendly](https://calendly.com) - Calendly is the tool for connecting and scheduling meetings. The free plan provides 1 Calendar connection per user and Unlimited sessions. Desktop and Mobile apps are also offered.
  * [cally.com](https://cally.com/) - Find the perfect time and date for a meeting. Simple to use, works great for small and large groups.
  * [cDox](https://cdox.ca) - Private document editor hosted in Canada. Write, format, collaborate, and publish documents with clean public links. Data is never used for AI training. Free plan includes 50 MB storage, up to 3 public links, and export to PDF, Word, and Markdown.
  * [Chanty.com](https://chanty.com/) - Chanty is another alternative to Slack. It has a free forever plan for small teams (up to 10) with unlimited public and private conversations, searchable history, unlimited 1:1 audio calls, unlimited voice messages, ten integrations, and 20 GB storage per team.
  * [DevToolLab](https://devtoollab.com) - Online developer tools offering free access to all basic tools, with the ability to auto save one entry per tool, standard processing speed, and community support.
  * [Discord](https://discord.com/) - Chat with public/private rooms. Markdown text, voice, video, and screen sharing capabilities. Free for unlimited users.
  * [Dubble](https://dubble.so/) - Free Step-by-Step Guide creator. Take screenshots, document processes and collaborate with your team. Also supports async screen recording.
  * [Duckly](https://duckly.com/) - Talk and collaborate in real time with your team. Pair programming with IDE, terminal sharing, voice, video, and screen sharing. Free for small teams.
  * [element.io](https://element.io/) - A decentralized and open-source communication tool built on Matrix. Group chats, direct messaging, encrypted file transfers, voice and video chats, and easy integration with other services.
  * [evernote.com](https://evernote.com/) - Tool for organizing information. Share your notes and work together with others
  * [Fibery](https://fibery.io/) - Connected workspace platform. Free for single users, up to 2 GB disk space.
  * [Fibo](https://fibo.dev) - A free online realtime scrum poker tool for agile teams that lets unlimited members estimate story points for faster planning.
  * [Fizzy](https://www.fizzy.do/) - Kanban-based platform for project management and issue tracking. Create public boards, set up webhooks, use card stamping, and track unlimited users - free for up to 1000 items.
  * [flat.social](https://flat.social) - Interactive customizable spaces for team meetings & happy hours socials. Unlimited meetings, free up to 8 concurrent users.
  * [flock.com](https://flock.com) - A faster way for your team to communicate. Free Unlimited Messages, Channels, Users, Apps & Integrations
  * [GitBook](https://www.gitbook.com/) - Platform for capturing and documenting technical knowledge - from product docs to internal knowledge bases and APIs. Free plan for individual developers.
  * [GitDailies](https://gitdailies.com) - Daily reports of your team's Commit and Pull Request activity on GitHub. Includes Push visualizer, peer recognition system, and custom alert builder. The free tier has unlimited users, three repos, and 3 alert configs.
  * [gitter.im](https://gitter.im/) - Chat, for GitHub. Unlimited public and private rooms, free for teams of up to 25
  * [gokanban.io](https://gokanban.io) - Syntax-based, no registration Kanban Board for fast use. Free with no limitations.
  * [Hackmd.io](https://hackmd.io/) - Real time collaboration & writing tool for markdown format docs/files. Like Google Docs but for markdown files. Free unlimited number of "notes", but the number of collaborators (invitee) for private notes & template [will be limited](https://hackmd.io/pricing).
  * [HeySpace](https://hey.space) - Task management tool with chat, calendar, timeline and video calls. Free for up to 5 users.
  * [Huly](https://huly.io/) - All-in-One Project Management Platform (alternative to Linear, Jira, Slack, Notion, Motion) - unlimited users, 10GB storage per workspace, 10GB video(audio) traffic.
  * [Keybase](https://keybase.io/) - Keybase is a FOSS alternative to Slack; it keeps everyone's chats and files safe, from families to communities to companies.
  * [Knocket](https://trtc.io/solutions/knocket) - Free-forever contact layer for indie developers and small teams: live chat widget for websites and mobile apps (iOS/Android/Flutter/React Native via WebView), a shareable contact page (Linktree-style with socials, booking links, and blog), and a unified Telegram/email inbox. Reply from Telegram directly (no dashboard needed). Meeting scheduler, multi-language, light/dark themes. Companion open-source AI auto-reply agent. No ads, no seat limits.
  * [Linkinize](https://linkinize.com) - Bookmark manager for teams with tagging, multi-workspaces, and collaboration. Free plan includes 4 workspaces and 10 team members.
  * [Lockitbot](https://www.lockitbot.com/) - Reserve and lock shared resources within Slack like Rooms, Dev environments , servers etc. Free for upto 2 resources
  * [meet.jit.si](https://meet.jit.si/) - One-click video conversations, and screen sharing, for free
  * [Miro](https://miro.com/) - Scalable, secure, cross-device, and enterprise-ready collaboration whiteboard for distributed teams. With a freemium plan.
  * [Notion](https://www.notion.so/) - Notion is a note-taking and collaboration application with markdown support that integrates tasks, wikis, and databases. The company describes the app as an all-in-one workspace for note-taking, project management and task management. In addition to cross-platform apps, it can be accessed via most web browsers.
  * [Nuclino](https://www.nuclino.com) - A lightweight and collaborative wiki for all your team's knowledge, docs, and notes. Free plan with all essential features, up to 50 items, and 5GB storage.
  * [OnlineInterview.io](https://onlineinterview.io/) - Free code interview platform with embedded video chat, drawing board, and online code editor where you can compile and run your code on the browser. You can create a remote interview room with just one click.
  * [paste.sh](https://paste.sh/) - This is a JavaScript and the Crypto based simple paste site.
  * [Pastefy](https://pastefy.app/) - Beautiful and simple Pastebin with optional Client-Encryption, Multitab-Pastes, an API, a highlighted Editor and more.
  * [Pendulums](https://pendulums.io/) - Pendulums is a free time tracking tool that helps you manage your time in a better manner with an easy-to-use interface and valuable statistics.
  * [Proton Pass](https://proton.me/pass) - Password manager with built-in email aliases, 2FA authenticator, sharing and passkeys. Available on web, browser extension, and mobile app and desktop.
  * [Pullflow](https://pullflow.com) - Pullflow offers an AI-enhanced platform for code review collaboration across GitHub, Slack, and VS Code.
  * [Pumble](https://pumble.com) - Free team chat app. Unlimited users and message history, free forever.
  * [Quidlo Timesheets](https://www.quidlo.com/timesheets) - A simple timesheet and time tracking app for teams. The free plan has time tracking and generating reports features for up to 10 users.
  * [Raindrop.io](https://raindrop.io) - Private and secure bookmarking app for macOS, Windows, Android, iOS, and Web. Free Unlimited Bookmarks and Collaboration.
  * [Revolt.chat](https://revolt.chat/) - An OpenSource alternative for[Discord](https://discord.com/), that respects your privacy. It also have most proprietary features from discord for free. Revolt is a all in one application that is secure and fast, while being 100% free. every features are free. They also have (official & unofficial) plugins support unlike most main-stream chatting applications.
  * [Rocket.Chat](https://rocket.chat/) - Open-source communication platform with Omnichannel features, Matrix Federation, Bridge with others apps, Unlimited messaging, and Full messaging history.
  * [ruttl.com](https://ruttl.com/) - The best all-in-one feedback tool to collect digital feedback and review websites, PDFs, and images.
  * [Screen Sharing via Browser](https://screensharing.net) - Free screen sharing tool, share your screen with collabrators right from your browser, no download or registration needed. For free.
  * [seafile.com](https://www.seafile.com/) - Private or cloud storage, file sharing, sync, discussions. The cloud version has just 1 GB
  * [SiteDots](https://sitedots.com/) - Share feedback for website projects directly on your website, no emulation, canvas or workarounds. Completely functional free tier.
  * [Slab](https://slab.com/) - A modern knowledge management service for teams. Free for up to 10 users.
  * [slack.com](https://slack.com/) - Free for unlimited users with some feature limitations
  * [StatusPile](https://www.statuspile.com/) - A status page of status pages. Could you track the status pages of your upstream providers?
  * [Stickies](https://stickies.app/) - Visual collaboration app used for brainstorming, content curation, and notes. Free for up to 3 Walls, unlimited users, and 1 GB storage.
  * [MeetBackdrops](https://meetbackdrops.com) - Free HD virtual backgrounds for video calls on Zoom, Microsoft Teams, and Google Meet. 1,000+ studio-designed environments with no signup required.
  * [talky.io](https://talky.io/) - Free group video chat. Anonymous. Peer‑to‑peer. No plugins, signup, or payment required
  * [Teamcamp](https://www.teamcamp.app) - All-in-one project management application for software development companies.
  * [Teamhood](https://teamhood.com/) - Free Project, Task, and Issue-tracking software. Supports Kanban with Swimlanes and full Scrum implementation. Has integrated time tracking. Free for five users and three project portfolios.
  * [Teamplify](https://teamplify.com) - improve team development processes with Team Analytics and Smart Daily Standup. Includes full-featured Time Off management for remote-first teams. Free for small groups of up to 5 users.
  * [Telegram](https://telegram.org/) - Telegram is for everyone who wants fast, reliable messaging and calls. Business users and small teams may like the large groups, usernames, desktop apps, and powerful file-sharing options.
  * [Tencent RTC](https://trtc.io/) - Tencent Real-Time Communication (TRTC) offers solutions for group audio/video calls.10,000 free minutes/month for the first year.
  * [TimeCamp](https://www.timecamp.com/) - Free time tracking software for unlimited users. Easily integrates with PM tools like Jira, Trello, Asana, etc.
  * [tldraw.com](https://tldraw.com) -  Free open-source white-boarding and diagramming tool with intelligent arrows, snapping, sticky notes, and SVG export features. Multiplayer mode for collaborative editing. Free official VS Code extension available as well.
  * [transfernow](https://www.transfernow.net/) - simplest, fastest and safest interface to transfer and share files. Send photos, videos and other large files without a mandatory subscription.
  * [Tugboat](https://tugboat.qa) - Preview every pull request, automated and on-demand. Free for all, complimentary Nano tier for non-profits.
  * [twist.com](https://twist.com) - An asynchronous-friendly team communication app where conversations stay organized and on-topic. Free and Unlimited plans are available. Discounts are provided for eligible teams.
  * [userforge.com](https://userforge.com/) - Interconnected online personas, user stories and context mapping.  Helps keep design and dev in sync free for up to 3 personas and two collaborators.
  * [Visual Debug](https://visualdebug.com) - A Visual feedback tool for better client-dev communication
  * [Webex](https://www.webex.com/) - Video meetings with a free plan offering 40 minutes per meeting with 100 attendees.
  * [Webvizio](https://webvizio.com) - Website feedback tool, website review software, and bug reporting tool for streamlining web development collaboration on tasks directly on live websites and web apps, images, PDFs, and design files.
  * [whereby.com](https://whereby.com/) - One-click video conversations, for free (formerly known as appear.in)
  * [windmill.dev](https://windmill.dev/) - Windmill is an open-source developer platform to quickly build production-grade multi-step automation and internal apps from minimal Python and Typescript scripts. As a free user, you can create and be a member of at most three non-premium workspaces.
  * [wistia.com](https://wistia.com/) - Video hosting with viewer analytics, HD video delivery, and marketing tools to help understand your visitors, 25 videos, and Wistia branded player
  * [wormhol.org](https://www.wormhol.org/) - Straightforward file sharing service. Share unlimited files up to 5GB with as many peers as you want.
  * [Wormhole](https://wormhole.app/) - Share files up to 5GB with end-to-end encryption for up to 24hours. For files larger than 5 GB, it uses peer-to-peer transfer to send your files directly.
  * [zoom.us](https://zoom.us/) - Secure Video and Web conferencing add-ons available. The free plan is limited to 40 minutes.
  * [Zulip](https://zulip.com/) - Real-time chat with a unique email-like threading model. The free plan includes 10,000 messages of search history and File storage up to 5 GB. also, it provides a self-hostable open-source version.
  * [RightFeature](https://rightfeature.com/) - Easily collect feedback from your customers, turn customer feedback into your product roadmap. Collect, prioritize, and ship features that actually matter to your users.

**[⬆️ Back to Top](#table-of-contents)**

## CMS

  * [Contentful](https://www.contentful.com/) - Headless CMS. Content management and delivery APIs in the cloud. Comes with one free Community space that includes five users, 25K records, 48 Content Types, 2 locales.
  * [Cosmic](https://www.cosmicjs.com/) - Headless CMS and API toolkit. Free personal plans for developers.
  * [Crystallize](https://crystallize.com) - Headless PIM with ecommerce support. Built-in GraphQL API. The free version includes unlimited users, 1000 catalog items, 5 GB/month bandwidth, and 25k/month API calls.
  * [DatoCMS](https://www.datocms.com/) - Offers free tier for small projects. DatoCMS is a GraphQL-based CMS. On the lower tier, you have 100k/month calls.
  * [Hygraph](https://hygraph.com/) - Offers free tier for small projects. GraphQL first API. Move away from legacy solutions to the GraphQL native Headless CMS - and deliver omnichannel content API first.
  * [Prismic](https://www.prismic.io/) - Headless CMS. Content management interface with fully hosted and scalable API. The Community Plan provides unlimited API calls, documents, custom types, assets, and locales to one user. Everything that you need for your next project. Bigger free plans are available for Open Content/Open Source projects.
  * [Sanity.io](https://www.sanity.io/) - Platform for structured content with an open-source editing environment and a real-time hosted data store. Unlimited projects. Unlimited admin users, three non-admin users, two datasets, 500K API CDN requests, 10GB bandwidth, and 5GB assets included for free per project.
  * [Solo](https://soloist.ai) - Free AI website creator from Mozilla, create a beautiful website for your business from a few simple inputs. Free custom domain, no credit card needed.
  * [Squidex](https://squidex.io/) - Offers free tier for small projects. API / GraphQL first. Open source and based on event sourcing (versing every change automatically).
  * [Storyblok](https://www.storyblok.com) - A Headless CMS for developers and marketers that works with all modern frameworks. The Community (free) tier offers Management API, Visual Editor, ten sources, Custom Field Types, Internationalization (unlimited languages/locales), Asset Manager (up to 2500 assets), Image Optimizing Service, Search Query, Webhook + 250GB Traffic/month included.
  * [TinaCMS](https://tina.io/) - Replacing Forestry.io. Open source Git-backed headless CMS that supports Markdown, MDX, and JSON. The basic offer is free with two users available.
  * [WPJack](https://wpjack.com) - Set up WordPress on any cloud in less than 5 minutes! The free tier includes 1 server, 2 sites, free SSL certificates, and unlimited cron jobs. No time limits or expirations-your website, your way.

**[⬆️ Back to Top](#table-of-contents)**

## Code Generation

* [Appinvento](https://appinvento.io/) - A free no-code app builder. It provides complete access to the automatically generated backend source code and allows for unlimited APIs and routes. The free plan includes three projects and five tables.
* [DhiWise](https://www.dhiwise.com/) - Converts Figma designs into dynamic Flutter and React applications. Its code generation technology is designed to optimize workflows for building production-ready mobile and web experiences.
* [Karbon Sites](https://www.karbonsites.space) - An AI-powered site builder and editor that generates production-ready frontend code from text prompts, sketches, or resumes. Features include native Android (APK) export and a free tier with 5 generations per month (unlimited via custom Gemini API key).
* [Metalama](https://www.postsharp.net/metalama) - A C#-specific tool that generates boilerplate code on the fly during compilation to keep source code clean. It is free for open-source projects; its commercial-friendly free tier includes up to three aspects.
* [Supermaven](https://www.supermaven.com/) - A high-speed AI code completion plugin for VS Code, JetBrains, and Neovim. The free tier provides unlimited inline completions with a focus on ultra-low latency.
* [v0.dev](https://v0.dev/) - Created by Vercel, v0 generates copy-and-paste friendly React code using shadcn/ui and Tailwind CSS. It uses a credit system, providing 1,200 starting credits and 200 free credits monthly.

**[⬆️ Back to Top](#table-of-contents)**

## Code Quality

  * [beanstalkapp.com](https://beanstalkapp.com/) - A complete workflow to write, review, and deploy code), a free account for one user, and one repository with 100 MB of storage
  * [codacy.com](https://www.codacy.com/) - Automated code reviews for PHP, Python, Ruby, Java, JavaScript, Scala, CSS, and CoffeeScript, free for unlimited public and private repositories
  * [Codeac.io](https://www.codeac.io/infrastructure-as-code.html?ref=free-for-dev) - Automated Infrastructure as Code review tool for DevOps integrates with GitHub, Bitbucket, and GitLab (even self-hosted). In addition to standard languages, it also analyzes Ansible, Terraform, CloudFormation, Kubernetes, and more. (open-source free)
  * [codecov.io](https://codecov.io/) - Code coverage tool (SaaS), free for Open Source and one free private repo
  * [CodeFactor](https://www.codefactor.io) - Automated Code Review for Git. The free version includes unlimited users, public repositories, and one private repo.
  * [coderabbit.ai](https://coderabbit.ai) - AI-powered code review tool that integrates with GitHub/GitLab. Free tier includes 200 files/hour, 3 reviews per hour, and 50 conversations/hour. Free forever for open source projects.
  * [CodSpeed](https://codspeed.io) - Automate performance tracking in your CI pipelines. Catch performance regressions before deployment, thanks to precise and consistent metrics. Free forever for Open Source projects.
  * [coveralls.io](https://coveralls.io/) - Display test coverage reports, free for Open Source
  * [deepscan.io](https://deepscan.io) - Advanced static analysis for automatically finding runtime errors in JavaScript code, free for Open Source
  * [DeepSource](https://deepsource.io/) - DeepSource continuously analyzes source code changes, finding and fixing issues categorized under security, performance, anti-patterns, bug-risks, documentation, and style. Native integration with GitHub, GitLab, and Bitbucket.
  * [DiffText](https://difftext.com) - Instantly find the differences between two blocks of code. Completely free to use.
  * [eversql.com](https://www.eversql.com/) - EverSQL - The #1 platform for database optimization. Gain critical insights into your database and SQL queries automatically.
  * [gerrithub.io](https://review.gerrithub.io/) - Gerrit code review for GitHub repositories for free
  * [goreportcard.com](https://goreportcard.com/) - Code Quality for Go projects, free for Open Source
  * [gtmetrix.com](https://gtmetrix.com/) - Reports and thorough recommendations to optimize websites
  * [holistic.dev](https://holistic.dev/) - The #1 static code analyzer for Postgresql optimization. Performance, security, and architect database issues automatic detection service
  * [houndci.com](https://houndci.com/) - Comments on GitHub commits about code quality, free for Open Source
  * [reviewable.io](https://reviewable.io/) - Code review for GitHub repositories, free for public or personal repos.
  * [scan.coverity.com](https://scan.coverity.com/) - Static code analysis for Java, C/C++, C# and JavaScript, free for Open Source
  * [scrutinizer-ci.com](https://scrutinizer-ci.com/) - Continuous inspection platform, free for Open Source
  * [semanticdiff.com](https://app.semanticdiff.com/) - Programming language aware diff for GitHub pull requests and commits, free for public repositories
  * [shields.io](https://shields.io) - Quality metadata badges for open source projects
  * [sonarcloud.io](https://sonarcloud.io) - Automated source code analysis for Java, JavaScript, C/C++, C#, VB.NET, PHP, Objective-C, Swift, Python, Groovy and even more languages, free for Open Source

**[⬆️ Back to Top](#table-of-contents)**

## Code Search and Browsing

  * [CodeKeep](https://codekeep.io) - Google Keep for Code Snippets. Organize, Discover, and share code snippets, featuring a powerful code screenshot tool with preset templates and a linking feature.
  * [libraries.io](https://libraries.io/) - Search and dependency update notifications for 32 different package managers, free for open source
  * [Namae](https://namae.dev/) - Search various websites like GitHub, Gitlab, Heroku, Netlify, and many more for the availability of your project name.
  * [tickgit.com](https://www.tickgit.com/) - Surfaces `TODO` comments (and other markers) to identify areas of code worth returning to for improvement.

**[⬆️ Back to Top](#table-of-contents)**

## CI and CD

  * [appcircle.io](https://appcircle.io) - An enterprise-grade mobile DevOps platform that automates the build, test, and publish store of mobile apps for faster, efficient release cycle. Free for 30 minutes max build time per build, 20 monthly builds and 1 concurrent build.
  * [appveyor.com](https://www.appveyor.com/) - CD service for Windows, free for Open Source
  * [bitrise.io](https://www.bitrise.io/) - A CI/CD for mobile apps, native or hybrid. With 200 free builds/month 10 min build time and two team members. OSS projects get 45 min build time, +1 concurrency and unlimited team size.
  * [buddy.works](https://buddy.works/) - A CI/CD with five free projects and one concurrent run (120 executions/month)
  * [Buildkite](https://buildkite.com) - CI Pipelines free for 3 users and 5k job minutes/month. Test Analytics free
    developer tier includes 100k test executions/month, with more free inclusions for open-source projects.
  * [bytebase.com](https://www.bytebase.com/) - Database CI/CD and DevOps. Free under 20 users and ten database instances
  * [CircleCI](https://circleci.com/) - Comprehensive free plan with all features included in a hosted CI/CD service for GitHub, GitLab, and BitBucket repositories. Multiple resource classes, Docker, Windows, Mac OS, ARM executors, local runners, test splitting, Docker Layer Caching, and other advanced CI/CD features. Free for up to 6000 minutes/month execution time, unlimited collaborators, 30 parallel jobs in private projects, and up to 80,000 free build minutes for Open Source projects.
  * [cirun.io](https://cirun.io) - Free for public GitHub repositories
  * [codemagic.io](https://codemagic.io/) - Free 500 build minutes/month
  * [deployhq.com](https://www.deployhq.com/) - 1 project with ten daily deployments (30 build minutes/month)
  * [LocalOps](https://localops.co/) - Deploy your app on AWS/GCP/Azure in under 30 minutes. Setup standardised app environments on any cloud, which come with in-built continuous deployment automation and advanced observability. The free plan allows 1 user and 1 app environment.
  * [Make](https://www.make.com/en) - The workflow automation tool lets you connect apps and automate workflows using UI. It supports many apps and the most popular APIs. Free for public GitHub repositories, and free tier with 100 Mb, 1000 Operations, and 15 minutes of minimum interval.
  * [Mergify](https://mergify.com) - workflow automation and merge queue for GitHub - Free for public GitHub repositories
  * [Nx Cloud](https://nx.dev/ci) - Nx Cloud speeds up your monorepos on CI with features such as remote caching, distribution of tasks across machines and even automated splitting of your e2e test runs. It comes with a free plan for up to 30 contributors with generous 150k credits included.
  * [RunMyJob](https://runmyjob.io) - Run GitHub Actions and GitLab CI pipelines smarter with real-time scaling Spike Instances. Free tier includes 400 vCPU-minutes, 800 GB-minutes, and 10 concurrent jobs with high-performance runners (12 vCPU and 32 GB RAM per job).
  * [Shipfox](https://www.shipfox.io/) - Run your GitHub actions 2x faster, 3.000 build minutes free each month.
  * [Spacelift](https://spacelift.io/) - Management platform for Infrastructure as Code. Free plan features: IaC collaboration, Terraform module registry, ChatOps integration, Continuous resource compliance with Open Policy Agent, SSO with SAML 2.0, and access to public worker pools: up to 200 minutes/month
  * [Squash Labs](https://www.squash.io/) - creates a VM for each branch and makes your app available from a unique URL, Unlimited public & private repos, Up to 2 GB VM Sizes.
  * [Terramate](https://terramate.io/) - Terramate is an orchestration and management platform for Infrastructure as Code (IaC) tools such as Terraform, OpenTofu, and Terragrunt. Free up to 2 users including all features.
  * [Terrateam](https://terrateam.io) - GitOps-first Terraform automation with pull request-driven workflows, project isolation via self-hosted runners, and layered runs for ordered operations. Free for up to 3 users.

**[⬆️ Back to Top](#table-of-contents)**

## Testing

  * [Appetize](https://appetize.io) - Test your Android & iOS apps on this Cloud Based Android Phone / Tablets emulator and iPhone/iPad simulators directly in your browser. The free tier includes two concurrent session with 30 minutes of usage per month. No limit on app size.
  * [Argos](https://argos-ci.com) - Open Source visual testing for developers. Unlimitedprojects, with 5,000 screenshots per month. Free for open-source projects.
  * [Bencher](https://bencher.dev/) - A continuous benchmarking tool suite to catch CI performance regressions. Free for all public projects.
  * [BugBug](https://bugbug.io/) - Lightweight test automation tool for web applications. It is easy to learn and doesn't require coding. You can run unlimited tests on your own computer for free. You also get cloud monitoring and CI/CD integration for an additional monthly fee.
  * [checkbot.io](https://www.checkbot.io/) - Browser extension that tests if your website follows 50+ SEO, speed and security best practices. Free tier for smaller websites.
  * [Checkly](https://checklyhq.com) - Code-first synthetic monitoring for modern DevOps. Monitor your APIs and apps at a fraction of the price of legacy providers. Powered by a Monitoring as Code workflow and Playwright. Generous free tier for devs.
  * [CORS-Tester](https://cors-error.dev/cors-tester/) - A free tool for developers and API testers to check if an API is CORS-enabled for a given domain and identify gaps. Get actionable insights.
  * [cypress.io](https://www.cypress.io/) - Fast, easy and reliable testing for anything that runs in a browser. Cypress Test Runner is always free and open-source with no restrictions and limitations. Cypress Dashboard is free for open-source projects for up to 5 users.
  * [everystep-automation.com](https://www.everystep-automation.com/) - Records and replays all steps made in a web browser and creates scripts, free with fewer options
  * [gridlastic.com](https://www.gridlastic.com/) - Selenium Grid testing with a free plan of up to 4 simultaneous selenium nodes/10 grid starts/4,000 test minutes/month
  * [katalon.com](https://katalon.com) - Provides a testing platform that can help teams of all sizes at different levels of testing maturity, including  Katalon Studio, TestOps (+ Visual Testing free), TestCloud, and Katalon Recorder.
  * [Keploy](https://keploy.io/) - Keploy is a functional testing toolkit for developers. Recording API calls generates E2E tests for APIs (KTests) and mocks or stubs(KMocks). It is free for Open Source projects.
  * [Lastest](https://lastest.cloud) - Ship fast. Don't break things. AI-supported visual verification and tests you can actually trust. Free forever plan: 1 project, 500 runner-minutes/mo, 1 concurrent run, no credit card.
  * [loadmill.com](https://www.loadmi

