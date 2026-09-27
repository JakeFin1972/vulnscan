"""Default content for the BIA / DPIA tool.

Everything in DEFAULT_CONFIG is editable by an admin at runtime (via the
Admin console's structured editors, or the raw JSON editor for anything
without a dedicated screen) -- nothing here is hard-coded into the
application logic except the key *names* used to wire up scoring
(see app/scoring.py for the small set of "role" markers it looks for).

Provenance note: most question text, guidance, and the option lists
below (impact scale, delivery model, information sub-domains, legal
grounds, "who provided the data", collection methods, international
transfer mechanisms) are taken directly from the source spreadsheet's
BIA / DPIA / Filters / Impact Scales / Classification Matrix / Important
Information Assets tabs. A handful of option lists -- "data subject
types", "personal data types", and "special category data types" --
were not backed by an explicit dropdown in the source file (those DPIA
cells were free text), so reasonable multi-select option lists were
authored for usability. They, like everything else, can be edited or
removed by an admin.
"""

DEFAULT_ORG_NAME = "Your Company"

DEFAULT_SETTINGS = {
    "dpia_profile_threshold": 2000,
    "dpia_risk_thresholds": {"critical": 20, "high": 12, "medium": 4, "low": 1},
    "support_contact": "your organization's Information Security or Data Privacy team",
}

OPTION_LISTS = {
    "impact_scale": [
        {"value": 5, "label": "Critical", "classification": 4, "protection_profile": "High", "service_level": "SL1"},
        {"value": 4, "label": "Major", "classification": 3, "protection_profile": "High", "service_level": "SL2"},
        {"value": 3, "label": "Moderate", "classification": 2, "protection_profile": "Elevated", "service_level": "SL3"},
        {"value": 2, "label": "Minor", "classification": 1, "protection_profile": "Minimum", "service_level": "Best effort"},
        {"value": 1, "label": "Insignificant", "classification": "N/A", "protection_profile": "Minimum", "service_level": "N/A"},
        {"value": 0, "label": "Not applicable", "classification": "<assessment not completed>", "protection_profile": "<assessment not completed>", "service_level": "N/A"},
        {"value": -1, "label": "Not set", "classification": "<assessment not completed>", "protection_profile": "<assessment not completed>", "service_level": "<assessment not completed>"},
    ],
    "yes_no": [
        {"value": "Yes", "label": "Yes"},
        {"value": "No", "label": "No"},
    ],
    "delivery_model": [
        {"value": "hosted_third_party", "label": "Hosted by third party"},
        {"value": "internal_dc", "label": "Internal Data Center"},
        {"value": "country_service_office", "label": "Country Service Office"},
        {"value": "saas", "label": "SaaS"},
        {"value": "paas", "label": "PaaS"},
        {"value": "iaas", "label": "IaaS"},
        {"value": "hybrid", "label": "Hybrid, please describe"},
        {"value": "na", "label": "N/A"},
    ],
    "info_subdomain": [
        {"value": "customer_personal_data", "label": "Customer Personal Data"},
        {"value": "sensitive_customer_personal_data", "label": "Sensitive Customer Personal Data"},
        {"value": "card_transaction_information", "label": "Card Transaction Information"},
        {"value": "cardholder_data", "label": "Cardholder data"},
        {"value": "authentication_data", "label": "Authentication Data"},
        {"value": "financial_information", "label": "Financial Information"},
        {"value": "strategic_business_information", "label": "Strategies and strategical business information"},
        {"value": "trading_information", "label": "Trading information"},
        {"value": "short_term_corporate_secrets", "label": "Short-term corporate secrets"},
        {"value": "incident_reporting", "label": "Incident reporting"},
        {"value": "contracts_and_agreements", "label": "Contracts and agreements"},
        {"value": "coworker_personal_data", "label": "Co-worker Personal Data"},
        {"value": "sensitive_coworker_personal_data", "label": "Sensitive Co-worker Personal Data"},
        {"value": "marketing", "label": "Marketing"},
        {"value": "other", "label": "Other, please specify"},
    ],
    "legal_grounds": [
        {"value": "consent", "label": "Consent"},
        {"value": "contract_performance", "label": "Contract performance"},
        {"value": "legal_obligation", "label": "Legal obligation"},
        {"value": "vital_interest", "label": "Vital interest"},
        {"value": "legitimate_interest", "label": "Legitimate interest"},
        {"value": "public_interest", "label": "Public interest"},
    ],
    "data_provided_by": [
        {"value": "individuals_themselves", "label": "Individuals themselves"},
        {"value": "third_parties", "label": "Third parties"},
        {"value": "parents", "label": "Parents providing data of their children"},
        {"value": "existing_solutions", "label": "Existing solutions (please specify)"},
        {"value": "other", "label": "Other (please specify)"},
    ],
    "collection_method": [
        {"value": "online_web", "label": "Online (web)"},
        {"value": "csc_phone", "label": "CSC (phone)"},
        {"value": "csc_web_chat", "label": "CSC (web chat)"},
        {"value": "csc_mail_form", "label": "CSC (mail form)"},
        {"value": "csc_social_media", "label": "CSC (social media)"},
        {"value": "store_app", "label": "Store App"},
        {"value": "loyalty_kiosk", "label": "Loyalty programme (kiosk)"},
        {"value": "loyalty_web", "label": "Loyalty programme (web)"},
        {"value": "loyalty_paper", "label": "Loyalty programme (paper)"},
        {"value": "store_online_form", "label": "Store (online form)"},
        {"value": "store_paper", "label": "Store (paper)"},
        {"value": "existing_solutions", "label": "Existing solutions (please specify)"},
        {"value": "other", "label": "Other, please specify"},
    ],
    "international_transfer": [
        {"value": "adequacy_decision", "label": "Adequacy decision"},
        {"value": "bcr", "label": "Binding corporate rules (BCR)"},
        {"value": "scc", "label": "Data protection contractual clauses"},
        {"value": "codes_of_conduct", "label": "Codes of conduct and certification mechanisms"},
        {"value": "ad_hoc_clauses", "label": "Ad hoc contractual clauses"},
        {"value": "international_agreement", "label": "International agreement"},
        {"value": "derogations", "label": "Derogations (e.g. consent, performance of a contract, public interest, etc.)"},
        {"value": "not_applicable", "label": "Not applicable"},
    ],
    # Authored (not present as an explicit dropdown in the source file) -- see module docstring.
    "data_subject_types": [
        {"value": "customers", "label": "Customers"},
        {"value": "coworkers", "label": "Co-workers / employees"},
        {"value": "job_applicants", "label": "Job applicants"},
        {"value": "third_parties", "label": "Suppliers, contractors or other third parties"},
        {"value": "visitors", "label": "Website / app visitors"},
        {"value": "children", "label": "Children"},
        {"value": "other", "label": "Other, please specify"},
    ],
    "personal_data_types": [
        {"value": "contact_details", "label": "Contact details (name, address, phone, email)"},
        {"value": "identification_data", "label": "Identification data (ID/passport number, date of birth)"},
        {"value": "financial_data", "label": "Financial / payment data"},
        {"value": "employment_data", "label": "General employment data (see 2.2.1)"},
        {"value": "online_behavioural_data", "label": "Online identifiers / behavioural data"},
        {"value": "media", "label": "Images, video or audio recordings"},
        {"value": "other", "label": "Other, please specify"},
    ],
    "special_category_types": [
        {"value": "health", "label": "Health data"},
        {"value": "genetic", "label": "Genetic data"},
        {"value": "biometric", "label": "Biometric data"},
        {"value": "racial_ethnic", "label": "Racial or ethnic origin"},
        {"value": "political", "label": "Political opinions"},
        {"value": "religious", "label": "Religious or philosophical beliefs"},
        {"value": "trade_union", "label": "Trade union membership"},
        {"value": "sex_life", "label": "Sex life or sexual orientation"},
        {"value": "criminal", "label": "Criminal convictions or offences"},
        {"value": "cardholder", "label": "Payment card / cardholder data"},
        {"value": "tracking", "label": "Tracking technologies / geo-location"},
        {"value": "none", "label": "None"},
        {"value": "other", "label": "Other, please specify"},
    ],
}

BIA_SCREENING_QUESTIONS = [
    {
        "key": "bia.screening.q1_info_asset",
        "prompt": "What is the information asset processed in the current or future solution?",
        "guidance": "Personal data is data which can be used to identify a living individual (direct identification) or data which can be used along with other information in our possession, or likely to come into our possession, to identify an individual (indirect identification). Personal data is not just limited to structured data -- it can include images, video recordings, call recordings, blog posts or opinions, IP addresses and cookie files.",
        "input_type": "select",
        "option_list": "info_subdomain",
    },
    {
        "key": "bia.screening.q1b_sensitive_personal_data",
        "prompt": "Will special category / sensitive personal data be processed?",
        "guidance": "This is one of the questions used to determine whether a full Data Privacy Impact Assessment (DPIA) is required, together with the answers below.",
        "input_type": "yesno",
        "option_list": "yes_no",
        "role": "sensitive_personal_data",
    },
    {
        "key": "bia.screening.q2_profile_count",
        "prompt": "If personal data is processed, how many individual profiles (customer and/or co-worker) will be processed?",
        "guidance": "Impact will be determined together with your Information Security and Data Privacy specialist based on volume criteria; e.g. if more than the configured threshold, the solution might be considered critical.",
        "input_type": "number",
        "role": "profiles_count",
    },
    {
        "key": "bia.screening.q3_cross_border",
        "prompt": "Is data collected and stored in one country and then transferred to / accessed from another country, outside the initial country's data privacy law jurisdiction? Please specify where data is geographically located and from where it's accessed/transferred in the comment field, if relevant.",
        "guidance": "Data can, for instance, be collected and held in Sweden and be accessible by support staff located in India. This would be considered an international data transfer.",
        "input_type": "yesno",
        "option_list": "yes_no",
        "role": "cross_border_transfer",
    },
    {
        "key": "bia.screening.q4_data_flow",
        "prompt": "Has a data flow been defined describing how the information in the solution is shared with other systems and/or business processes?",
        "guidance": "A data flow diagram maps out the flow of information for any process or system, including the methods of data collection, and highlights eventual dependencies. This helps identify weak links, single points of failure and duplicates. If not attached elsewhere, reference where the diagram can be found in the comment field.",
        "input_type": "yesno",
        "option_list": "yes_no",
    },
    {
        "key": "bia.screening.q5_hosting_model",
        "prompt": "What is the hosted service model of the supplier/data processor of the solution?",
        "guidance": "A data processor is someone who processes the data on behalf of the data controller. If the solution is provided by a third party, select the hosted delivery model. If the solution is hosted locally, select N/A.",
        "input_type": "select",
        "option_list": "delivery_model",
    },
    {
        "key": "bia.screening.q6_integration_changes",
        "prompt": "Does the integration of the solution involve significant changes in other solutions?",
        "guidance": "If yes, describe the impact in the comment field.",
        "input_type": "yesno",
        "option_list": "yes_no",
    },
    {
        "key": "bia.screening.q7_retention_defined",
        "prompt": "Have data retention periods been defined?",
        "guidance": "If yes, attach relevant documentation or use the comment field to justify the data retention period.",
        "input_type": "yesno",
        "option_list": "yes_no",
    },
    {
        "key": "bia.screening.q8_access_responsibilities",
        "prompt": "Are responsibilities defined for approving the granting and removal of access privileges to the data?",
        "guidance": "If yes, specify the role(s) in the comment field.",
        "input_type": "yesno",
        "option_list": "yes_no",
    },
]


def _impact_question(key, prompt, category, guidance=None):
    q = {
        "key": key,
        "prompt": prompt,
        "guidance": guidance,
        "input_type": "impact",
        "option_list": "impact_scale",
        "category": category,
    }
    return q


BIA_CONFIDENTIALITY_QUESTIONS = [
    _impact_question("bia.confidentiality.q9", "What's the potential impact if the information is disclosed to the general public (including press, social media)?", "confidentiality"),
    _impact_question("bia.confidentiality.q10", "What's the potential impact if the information is obtained by a competitor?", "confidentiality"),
    _impact_question("bia.confidentiality.q11", "What's the impact if the information is obtained by an unauthorised internal party, consultant or supplier?", "confidentiality"),
    _impact_question("bia.confidentiality.q12", "What's the potential impact if information is given to the wrong customer or co-worker?", "confidentiality"),
    _impact_question("bia.confidentiality.q13", "What is the potential impact for other confidentiality scenarios that could be relevant? Describe the scenario in the comment field.", "confidentiality"),
]

BIA_INTEGRITY_QUESTIONS = [
    _impact_question("bia.integrity.q14", "What's the potential impact if the information is incorrect when given to the general public (including media)?", "integrity"),
    _impact_question("bia.integrity.q15", "What's the potential impact if the information is incorrect when given to authorities?", "integrity"),
    _impact_question("bia.integrity.q16", "What's the potential impact if the information is incorrect when processed in internal solutions?", "integrity"),
    _impact_question("bia.integrity.q17", "What's the potential impact if the information is incorrect when used in internal decision making?", "integrity"),
    _impact_question("bia.integrity.q18", "What's the potential worst impact for other integrity scenarios that could be relevant? Describe the scenario in the comment field.", "integrity"),
]

BIA_AVAILABILITY_QUESTIONS = [
    _impact_question("bia.availability.q19", "What's the potential impact if the information/system is unavailable for a prolonged time (more than one hour)?", "availability"),
    _impact_question("bia.availability.q20", "What's the potential impact if senior management can't access the information/system (unavailable for more than a day)?", "availability"),
    _impact_question("bia.availability.q21", "What's the potential impact if supervisory authorities, law enforcement or other authorities request data from this information/system, and it's not available (unavailable for more than a week)?", "availability"),
    _impact_question("bia.availability.q22", "What's the potential worst impact for other availability scenarios that could be relevant? Describe the scenario in the comment field.", "availability"),
]

BIA_UNIQUENESS_QUESTIONS = [
    _impact_question("bia.uniqueness.q23", "What's the potential impact if there is more than one data repository?", "uniqueness", "As an example, a product has different prices in store, catalogue and web."),
    _impact_question("bia.uniqueness.q24", "What's the potential impact if there are different definitions for an information asset?", "uniqueness", "As an example, there are different definitions of weekly sales or product weight."),
    _impact_question("bia.uniqueness.q25", "What's the potential impact if more than one information instance has the same unique identifier?", "uniqueness", "Two customers have the same unique customer ID."),
    _impact_question("bia.uniqueness.q26", "What's the potential worst impact for other uniqueness scenarios that could be relevant? Describe the scenario in the comment field.", "uniqueness"),
]

BIA_CONSISTENCY_QUESTIONS = [
    _impact_question("bia.consistency.q27", "What's the potential impact if the attribute values aren't in sync across systems and processes?", "consistency", "As an example, if stock level varies between two systems."),
    _impact_question("bia.consistency.q28", "What's the impact if the information contains any logical contradictions?", "consistency", "A product is listed as in stock in one solution and not in stock in another."),
    _impact_question("bia.consistency.q29", "What's the potential worst impact for other consistency scenarios that could be relevant? Describe the scenario in the comment field.", "consistency"),
]

BIA_COMPLIANCE_QUESTIONS = [
    _impact_question("bia.compliance.q30", "What's the potential impact if the management of data (e.g. storage, processing, sharing) does not comply with applicable legislation (e.g. GDPR, NIS2, DORA, other national data protection or financial law)? Specify the applicable regulations in the comment field.", "compliance"),
    _impact_question("bia.compliance.q31", "What's the potential impact if the management of data does not comply with industry standards (e.g. PCI DSS)? Specify the applicable standards in the comment field.", "compliance"),
    _impact_question("bia.compliance.q32", "What's the potential impact if the management of data does not conform to the organization's internal policies?", "compliance"),
    _impact_question("bia.compliance.q33", "What's the potential worst impact for other compliance scenarios (e.g. organization-specific principles) that could be relevant? Describe the scenario in the comment field.", "compliance"),
]

TOOL_BIA = {
    "key": "bia",
    "title": "Business Impact Assessment (BIA)",
    "description": "Use these questions to determine the potential impact if there is a loss of confidentiality (privacy), integrity or availability. For each scenario, consider the potential but realistic worst impact, without taking existing security controls into account.",
    "sections": [
        {
            "key": "screening",
            "title": "Screening questions",
            "description": "General questions about the type of data used in the current or future solution. These questions help determine whether a Data Privacy Impact Assessment (DPIA) should also be performed in addition to this BIA.",
            "questions": BIA_SCREENING_QUESTIONS,
        },
        {
            "key": "confidentiality",
            "title": "Confidentiality",
            "description": "Confidentiality relates to restricting access to information and solutions to authorised persons only, based on work role, need to know, clearance etc. A breach of confidentiality could result in information being disclosed to unauthorised parties.",
            "questions": BIA_CONFIDENTIALITY_QUESTIONS,
        },
        {
            "key": "integrity",
            "title": "Integrity",
            "description": "Integrity refers to the accuracy, consistency and authenticity of data over its entire lifecycle. A breach of integrity could result in unauthorized changes to data or incorrect data being used in solutions and processes.",
            "questions": BIA_INTEGRITY_QUESTIONS,
        },
        {
            "key": "availability",
            "title": "Availability",
            "description": "Availability refers to the correct functioning and accessibility of information and solutions. Issues with availability could mean information or solutions aren't working properly and business processes are disrupted.",
            "questions": BIA_AVAILABILITY_QUESTIONS,
        },
        {
            "key": "uniqueness",
            "title": "Uniqueness",
            "description": "Uniqueness refers to the duplication of information sources -- e.g. two customers sharing the same unique customer ID, leading to confusion over which record is correct.",
            "questions": BIA_UNIQUENESS_QUESTIONS,
        },
        {
            "key": "consistency",
            "title": "Consistency",
            "description": "Consistency refers to the correctness and uniformity of information or delivery of that information -- e.g. a customer's city and ZIP code not matching across systems.",
            "questions": BIA_CONSISTENCY_QUESTIONS,
        },
        {
            "key": "compliance",
            "title": "Regulatory compliance",
            "description": "Compliance refers to conformity and alignment with applicable laws, regulations and industry standards (e.g. GDPR, NIS2, DORA, PCI DSS). Issues with compliance could risk withdrawal of a certification or authorisation to operate.",
            "questions": BIA_COMPLIANCE_QUESTIONS,
        },
    ],
}

ART35_CRITERIA = [
    "Systematic and extensive evaluation of personal aspects based on automated processing, including profiling, with legal or similarly significant effect",
    "Large-scale processing of special category data (Art. 9) or criminal-conviction/offence data (Art. 10)",
    "Systematic monitoring of a publicly accessible area on a large scale",
    "Evaluation or scoring (incl. profiling/predicting) of performance, economic situation, health, preferences, reliability, behaviour, location or movements",
    "Automated decision-making with legal or similarly significant effect",
    "Sensitive data or data of a highly personal nature",
    "Data processed on a large scale (number of subjects, volume, duration, geographic extent)",
    "Matching or combining datasets",
    "Data concerning vulnerable data subjects",
    "Innovative use of new technological or organisational solutions",
    "Processing that prevents data subjects from exercising a right or using a service/contract",
    "Other (e.g. national list, DPO recommendation, data subject recommendation, code of conduct requirement)",
    "Existing high-risk processing where the risk context has since changed",
]


def _art35_question(i, text):
    return {
        "key": f"dpia0.art35.c{i}",
        "prompt": text,
        "guidance": "Mark whether this criterion applies to the processing. If any criterion applies, a full DPIA is recommended (WP248 rev.01, as reflected in the EDPB DPIA template).",
        "input_type": "yesno",
        "option_list": "yes_no",
        "role": "art35_criterion",
    }


TOOL_DPIA0 = {
    "key": "dpia0",
    "title": "DPIA - Overview & Scope",
    "description": "Follows the structure of the EDPB Template for Data Protection Impact Assessment. Use alongside the operational DPIA questions below, which are not duplicated here.",
    "sections": [
        {
            "key": "controllers",
            "title": "Controller(s)",
            "description": "",
            "questions": [
                {"key": "dpia0.controller_name", "prompt": "Controller name", "input_type": "text"},
                {"key": "dpia0.management_units", "prompt": "Management unit(s) responsible for the processing", "input_type": "textarea"},
                {"key": "dpia0.main_establishment", "prompt": "Main establishment / point of contact or representative", "input_type": "textarea"},
                {"key": "dpia0.dpo_contact", "prompt": "DPO (or similar function) - name and contact details", "input_type": "textarea"},
            ],
        },
        {
            "key": "processors",
            "title": "Processor(s) and sub-processor(s)",
            "description": "",
            "questions": [
                {"key": "dpia0.processor1_name", "prompt": "Processor 1 - name", "input_type": "text"},
                {"key": "dpia0.processor1_obligations", "prompt": "Processor 1 - definition of their obligations and tasks", "input_type": "textarea"},
                {"key": "dpia0.processor2_name", "prompt": "Processor 2 - name", "input_type": "text"},
                {"key": "dpia0.processor2_obligations", "prompt": "Processor 2 - definition of their obligations and tasks", "input_type": "textarea"},
                {"key": "dpia0.processor3_name", "prompt": "Processor 3 - name", "input_type": "text"},
                {"key": "dpia0.processor3_obligations", "prompt": "Processor 3 - definition of their obligations and tasks", "input_type": "textarea"},
            ],
        },
        {
            "key": "processing_name",
            "title": "Name of the processing",
            "description": "",
            "questions": [
                {"key": "dpia0.internal_name", "prompt": "Internal name given to the processing (as in the Record of Processing Activities)", "input_type": "text"},
                {"key": "dpia0.version_history", "prompt": "Current version (history of changes made to the processing, if any)", "input_type": "textarea"},
            ],
        },
        {
            "key": "planning",
            "title": "Planning of the processing",
            "description": "",
            "questions": [
                {"key": "dpia0.launch_date", "prompt": "Estimated launch date", "input_type": "date"},
                {"key": "dpia0.end_date", "prompt": "Estimated end date or expiry conditions (if applicable/temporary)", "input_type": "text"},
            ],
        },
        {
            "key": "technical_sheet",
            "title": "DPIA technical sheet",
            "description": "",
            "questions": [
                {"key": "dpia0.version_log", "prompt": "Current version and version log of this DPIA", "input_type": "textarea"},
                {"key": "dpia0.team_involved", "prompt": "Team involved in conducting this DPIA (roles, tasks, responsibilities)", "input_type": "textarea"},
                {"key": "dpia0.guidelines_used", "prompt": "Guidelines, standards, codes of conduct or other reference material used", "input_type": "textarea"},
                {"key": "dpia0.scope", "prompt": "Scope of this DPIA (what has been considered / left out, and why)", "input_type": "textarea"},
                {"key": "dpia0.completion_date", "prompt": "Completion date", "input_type": "date"},
                {"key": "dpia0.formal_validation", "prompt": "Formal validation date and approving official", "input_type": "text"},
                {"key": "dpia0.publish_externally", "prompt": "Is this DPIA (or parts of it) intended to be published or shared externally? If yes, how?", "input_type": "textarea"},
            ],
        },
        {
            "key": "art35_criteria",
            "title": 'Reasons this DPIA is being conducted (Art. 35(3) GDPR / WP248 criteria)',
            "description": "If any criterion applies, a full DPIA is recommended.",
            "questions": [_art35_question(i, text) for i, text in enumerate(ART35_CRITERIA, start=1)],
        },
    ],
}

DPIA_QUESTIONS_BY_SECTION = {
    "general_information": [
        {"key": "dpia.q1_1", "id": "1.1", "prompt": 'Provide a summary of the data processing activities associated with the project/solution. If the project involves implementing a new solution, indicate what the solution is used for.', "guidance": "Processing, in relation to personal data, means any action related to personal data, including but not limited to obtaining, recording, storing, updating, holding, altering, reading, analysing, transferring and deleting personal data.", "input_type": "textarea"},
    ],
    "data_collection": [
        {"key": "dpia.q2_1", "id": "2.1", "prompt": "Whose data are you collecting? Select the different types of people whose data will be processed.", "guidance": "Third parties are external suppliers, organisations or individuals contracted by the organization to use, handle or process the organization's assets or provide services to or on behalf of the organization (e.g. outsourcing providers, service providers, external consultants and contractors).", "input_type": "multiselect", "option_list": "data_subject_types"},
        {"key": "dpia.q2_2", "id": "2.2", "prompt": "What types of personal data will be collected?", "guidance": "Personal data is data which can be used to identify a living individual, directly or indirectly. It is not limited to structured data -- it can include images, video/call recordings, blog posts or opinions, IP addresses and cookie files.", "input_type": "multiselect", "option_list": "personal_data_types"},
        {"key": "dpia.q2_2_1", "id": "2.2.1", "prompt": "If you selected general employment data above, specify what type of employment data will be collected.", "guidance": "Organisational information may include company, department, position, job title, cost centre, manager, etc. Communication information may include chat, e-mail or ticketing tool data. Social media information may include internal social posts or comments.", "input_type": "textarea"},
        {"key": "dpia.q2_3", "id": "2.3", "prompt": "What types of sensitive personal data (special category data) will be collected?", "guidance": "Tracking technologies here refers to technologies that show where an individual has been browsing outside the organization's domain.", "input_type": "multiselect", "option_list": "special_category_types"},
        {"key": "dpia.q2_4", "id": "2.4", "prompt": "Who will provide the organization with personal data?", "input_type": "select", "option_list": "data_provided_by"},
        {"key": "dpia.q2_5", "id": "2.5", "prompt": "How will the personal data be collected?", "input_type": "multiselect", "option_list": "collection_method"},
        {"key": "dpia.q2_6", "id": "2.6", "prompt": "How will individuals be informed about why their personal data is being collected and how it may be used?", "guidance": "The organization has a legal obligation to ensure individuals are made aware how their personal data is being processed, e.g. through a privacy notice.", "input_type": "textarea"},
    ],
    "data_use": [
        {"key": "dpia.q3_1", "id": "3.1", "prompt": "What is the purpose(s) for which personal data is to be processed?", "guidance": "Be clear about the purpose(s) for which personal data is processed, so you can ensure data is processed in a way that is compatible with the original purpose.", "input_type": "textarea"},
        {"key": "dpia.q3_2", "id": "3.2", "prompt": "What is the legal basis for the processing? Specify for each type of personal data processed.", "guidance": "You must have a valid lawful basis to process personal data. Under the GDPR there are six available lawful bases: contract, legitimate interest, consent, legal obligation, vital interest, and public interest.", "input_type": "multiselect", "option_list": "legal_grounds"},
        {"key": "dpia.q3_2_1", "id": "3.2.1", "prompt": "If legitimate interest is used as the legal basis, specify the legitimate interest.", "guidance": "For example, background checks in recruitment and HR functions.", "input_type": "textarea"},
        {"key": "dpia.q3_2_2", "id": "3.2.2", "prompt": "If consent will be sought, specify how consent will be collected, recorded and stored.", "guidance": "Consent must be freely given, specific, informed and unambiguous. When recording consent, capture the time and date it was given.", "input_type": "textarea"},
        {"key": "dpia.q3_3", "id": "3.3", "prompt": "Will personal data be used for direct marketing?", "guidance": "Direct marketing is a form of advertising where organisations communicate directly to customers through a variety of media.", "input_type": "yesno", "option_list": "yes_no"},
        {"key": "dpia.q3_4", "id": "3.4", "prompt": "Will personal data be used for automated decision making, or profiling?", "guidance": "Profiling refers to any form of automated processing of personal data used to evaluate personal aspects, in particular to analyse or predict work performance, economic situation, health, personal preferences, interests, reliability, behaviour, location or movements.", "input_type": "yesno", "option_list": "yes_no"},
    ],
    "data_quality": [
        {"key": "dpia.q4_1", "id": "4.1", "prompt": "How will it be ensured that the quality of personal data will be maintained?", "guidance": "Personal data must be adequate, relevant and limited to the purpose for which it is processed, e.g. avoid duplication of records, ensure data is up to date.", "input_type": "textarea"},
    ],
    "data_storage": [
        {"key": "dpia.q5_1", "id": "5.1", "prompt": "Indicate and justify how long data will be held for.", "guidance": "List the data retention period(s) for different types of data, if applicable. E.g. 'Individual records are deleted after 5 years of inactivity.'", "input_type": "textarea"},
        {"key": "dpia.q5_2", "id": "5.2", "prompt": "Where will the personal data be stored (both paper and electronic copies, where relevant)?", "guidance": "E.g. electronic copies may be stored in shared drives, email inboxes.", "input_type": "textarea"},
        {"key": "dpia.q5_3", "id": "5.3", "prompt": "What will you do with the personal data upon expiry of the retention period?", "input_type": "textarea"},
    ],
    "data_sharing": [
        {"key": "dpia.q6_1", "id": "6.1", "prompt": "Will personal data be shared internally within the organisation? If yes, describe how, when and with which solutions personal data will be shared, and between which legal entities.", "input_type": "textarea"},
        {"key": "dpia.q6_2", "id": "6.2", "prompt": "Will personal data be shared with third parties? If yes, describe with whom and why.", "guidance": "Third parties are external suppliers, organisations or individuals contracted by the organization, including outsourcing providers, service providers, companies within the wider corporate group, external consultants and contractors.", "input_type": "yesno", "option_list": "yes_no"},
        {"key": "dpia.q6_2_1", "id": "6.2.1", "prompt": "If personal data will be shared with third parties, is there a Data Processing Agreement (DPA) in place?", "input_type": "yesno", "option_list": "yes_no"},
        {"key": "dpia.q6_3", "id": "6.3", "prompt": "Will personal data be transferred cross-border? If yes, list the countries involved in the comment field.", "input_type": "yesno", "option_list": "yes_no"},
        {"key": "dpia.q6_3_1", "id": "6.3.1", "prompt": "If personal data will be transferred cross-border, select the relevant data protection mechanism.", "guidance": "Adequacy decisions cover certain countries identified by regulators as adequately protecting personal data by law. Appropriate safeguards (e.g. BCRs, standard contractual clauses) let organisations commit to protect personal data for ongoing international transfers. Derogations may be used under limited circumstances.", "input_type": "select", "option_list": "international_transfer"},
    ],
    "access_management": [
        {"key": "dpia.q7_1", "id": "7.1", "prompt": "Indicate who will be responsible for authorising read and/or write privileges to access the data.", "input_type": "textarea"},
        {"key": "dpia.q7_2", "id": "7.2", "prompt": "Indicate the functions that will have access to the data and their level of access.", "input_type": "textarea"},
    ],
    "data_subject_rights": [
        {"key": "dpia.q8_1", "id": "8.1", "prompt": "Describe how requests from individuals for access to their own personal data will be handled.", "input_type": "textarea"},
        {"key": "dpia.q8_2", "id": "8.2", "prompt": "Describe how requests from individuals to delete or correct their personal data will be handled.", "input_type": "textarea"},
        {"key": "dpia.q8_3", "id": "8.3", "prompt": "If personal data will be used for direct marketing, describe how direct marketing opt-out requests will be handled.", "input_type": "textarea"},
        {"key": "dpia.q8_4", "id": "8.4", "prompt": "Describe how individuals can restrict the processing of their data.", "input_type": "textarea"},
    ],
}

_DPIA_SECTION_TITLES = {
    "general_information": "1. General Information",
    "data_collection": "2. Data Collection",
    "data_use": "3. Data Use",
    "data_quality": "4. Data Quality",
    "data_storage": "5. Data Storage",
    "data_sharing": "6. Data Sharing",
    "access_management": "7. Access Management",
    "data_subject_rights": "8. Data Subject Rights",
}


def _with_risk_register(questions):
    out = []
    for q in questions:
        q = dict(q)
        q["has_risk_register"] = True
        out.append(q)
    return out


TOOL_DPIA = {
    "key": "dpia",
    "title": "Data Privacy Impact Assessment (DPIA)",
    "description": "Detailed operational questions used to assess privacy risk. Each question carries its own risk register: identified risk, remediation options, likelihood x consequence scoring, impact flags, conclusion, owner, status and due date -- exactly like the source spreadsheet's per-question risk columns.",
    "sections": [
        {
            "key": key,
            "title": _DPIA_SECTION_TITLES[key],
            "description": "",
            "questions": _with_risk_register(questions),
        }
        for key, questions in DPIA_QUESTIONS_BY_SECTION.items()
    ],
}

IMPACT_SCALE_TABLE = [
    {"area": "Impact on brand and reputation", "area_description": "Reduced trust in the brand and loss of respect by the organization's stakeholders", "sub_area": "Impact on publicity (negative information published in media)", "levels": ["Local negative publicity, short term on a minor issue.", "Nation-wide negative publicity, short term on a minor issue.", "Continent-wide negative publicity and/or longer lasting nation-wide publicity with negative brand impact.", "World-wide negative publicity.", "Continuous world-wide negative publicity."]},
    {"area": "Impact on brand and reputation", "area_description": "", "sub_area": "Impact on regulators, authorities, customers and/or suppliers (loss of confidence caused by violation of regulatory, business, quality and/or safety standards)", "levels": ["Minor local loss of confidence and/or minor fines/actions imposed.", "Minor short term loss of confidence and/or minor fines/actions imposed.", "Moderate temporary loss of confidence and/or moderate fines/actions imposed.", "Major long-lasting loss of confidence and/or major fines, criminal charges, closure of building or operations in the short term (24 hours).", "Catastrophic loss of confidence and/or closure of building longer than 24 hours."]},
    {"area": "Impact on finance", "area_description": "Direct and indirect financial loss in direct and indirect business activities", "sub_area": "Impact on sales (loss of sales and/or margin)", "levels": ["< 1%", "~ 1%", "1% to 5%", "5% to 20%", "> 20%"]},
    {"area": "Impact on finance", "area_description": "", "sub_area": "Impact on penalties/legal liabilities (breach of legal and/or contractual obligations)", "levels": ["< €10K", "€10K to €100K", "€100K to €500K", "€500K to €1m", "> €1m"]},
    {"area": "Impact on finance", "area_description": "", "sub_area": "Impact on tangible assets (loss of assets through theft, fraud, conflict of interest etc.)", "levels": ["< €10K", "€10K to €250K", "€250K to €1m", "€1m to €10m", "> €10m"]},
    {"area": "Impact on finance", "area_description": "", "sub_area": "Impact on unforeseen costs (repair costs, investigation costs, increased insurance premiums, etc.)", "levels": ["< €10K", "€10K to €250K", "€250K to €1m", "€1m to €10m", "> €10m"]},
    {"area": "Impact on business and people", "area_description": "Discontinuity of direct and indirect business activities caused by impairment on both individual and/or company level", "sub_area": "Impact on productivity (reduced staff morale, reduced efficiency, lost time, and/or job losses)", "levels": ["Small temporary loss of productivity.", "Limited loss of productivity.", "Material/larger loss of productivity.", "Severe loss of productivity.", "Critical loss of productivity."]},
    {"area": "Impact on business and people", "area_description": "", "sub_area": "Impact on OH&S (occupational health and safety breaches)", "levels": ["Limited number of co-workers or third party staff feeling ill or unwell.", "Small injury where minimal medical treatment is required with up to 3 days off from workplace.", "Extensive injuries or long term serious illness and loss of time (more than 3 days).", "Fatality or permanent disability.", "Multiple fatalities or multiple permanent disabilities."]},
    {"area": "Impact on business and people", "area_description": "", "sub_area": "Impact on competitiveness (higher long term operational costs or prices, loss of market share, and/or loss of customers)", "levels": ["< 1%", "~ 1%", "1% to 5%", "5% to 20%", "> 20%"]},
    {"area": "Impact on business and people", "area_description": "", "sub_area": "New ventures held up (delayed new products, services, market entries, marketing activities, stores/shopping centres)", "levels": ["Less than one day.", "Delayed by less than one week.", "Delayed by weeks.", "Delayed by months.", "Delayed by year(s)."]},
    {"area": "Impact on business and people", "area_description": "", "sub_area": "Loss of management control (impaired decision-making, inability to monitor financial positions, process management failures)", "levels": ["Limited loss of control/time of local site management.", "Small loss of control/time of local/country management.", "Material/larger loss of control/time of local/country management and informing global management.", "Severe loss of control/time of local/country management and involvement of global management.", "Critical loss of control/time that cannot be handled in existing management structures, causing exceptional/temporary management (e.g. Emergency Response Team) to take over responsibility."]},
]

CLASSIFICATION_MATRIX = [
    {"aspect": "Confidentiality", "code": "C1", "label": "Public", "criteria": "No restrictions", "business_impact": "All information is generally accessible to everyone. Breach of this classification is not possible.", "controls": "No protections required against exposure and access. Label/tag document/e-mail with appropriate disclaimer and classification level.", "example_assets": "Advertising handout; published information; public internet web information."},
    {"aspect": "Confidentiality", "code": "C2", "label": "Internal", "criteria": "Co-workers", "business_impact": "Information which may or must be accessible to all co-workers. Confidentiality is low. Violation of this classification can cause some direct or indirect damage.", "controls": "No protection against exposure; protection against unauthorised access; encrypt when sending to/from external parties; verify external parties are under NDA prior to sending internal information; store portable devices/media in a locked cabinet if outside premises.", "example_assets": "Internal messages, contact books, calendars; reports/files/working papers of daily activities; organizational charts and job descriptions; policies and standards."},
    {"aspect": "Confidentiality", "code": "C3", "label": "Confidential", "criteria": "A limited group of persons only", "business_impact": "Information which is only accessible to a limited group of users, made available based on trust. Breach of this classification can cause serious direct or indirect damage.", "controls": "Access limited to a predefined group (e.g. project/business unit) as defined by the Information Owner; access can be granted to internal co-workers or external parties under NDA; email/portable storage is encrypted; database encryption enforced; segregation of duties enforced; stored only on secured storage with strict access control and strong authentication; document owner approval required before sharing; SDLC-developed solutions; portable devices/media returned to IT for disposal.", "example_assets": "Customer related information; distributor related information; co-worker salary/performance information; business contracts."},
    {"aspect": "Confidentiality", "code": "C4", "label": "Strictly confidential", "criteria": "Predefined and appointed persons only, stated by the right management level", "business_impact": "Sensitive data which should only be made available to the immediate recipient. Breach of this classification can cause (very) extensive damage.", "controls": "Exposure limited to one or a very few individuals as defined by the Information Owner; access only granted to co-workers with relevant management approval; protection against unauthorised access; procedures to delete information when not needed; stored only on secured storage (e.g. digital safe); multiple layers of encryption; attribute based access control; SDLC-developed solutions; monitored by DLP; independent/3rd party crypto key management.", "example_assets": "Passwords; encryption keys; payment transactions; strategic business plans, M&A information; consolidated financial data before publication; important draft contracts; top-management correspondence; information defined as strictly confidential by law or regulators."},
    {"aspect": "Integrity", "code": "I1", "label": "Uncontrolled", "criteria": "No protection and traceability is required", "business_impact": "The data may be altered. No extra protection of integrity is required. Breach of integrity results in no damage.", "controls": "No protection against unauthorized modifications or loss is needed or guaranteed. Traceability is not guaranteed.", "example_assets": "Program code; files; databases; file transfer; payment transactions; parameter settings; logs."},
    {"aspect": "Integrity", "code": "I2", "label": "Controlled", "criteria": "Protection against significant unauthorized information changes and traceability for vital changes is required", "business_impact": "A business process using this data allows some (integrity) mistakes. Basic-level security is required. Breach can cause some direct or indirect damage.", "controls": "Basic authentication; record authentication (correct/wrong) and time; record relevant input/output of an IT system or service; store monitored data; verify accuracy and completeness; traceability for significant changes; input validation."},
    {"aspect": "Integrity", "code": "I3", "label": "Reliable", "criteria": "Protection against unauthorized changes and traceability is required", "business_impact": "A business process using this data allows few (integrity) mistakes. Protection of integrity is essential. Breach can cause serious direct or indirect damage.", "controls": "Strong authentication; record authentication and time; record relevant input/output; store monitored data; verify accuracy and completeness; traceability for most changes; input validation; file integrity monitoring for binaries/config files; SDLC-developed solutions; pentests conducted."},
    {"aspect": "Integrity", "code": "I4", "label": "Verified", "criteria": "Protection against unauthorized changes and full traceability is required", "business_impact": "A business process using this data does not allow any (integrity) mistakes. Breach can cause (very) extensive damage.", "controls": "Strong authentication; 4-eye principle; record authentication and time; record relevant input/output; store monitored data; verify accuracy and completeness; traceability for all changes; input validation; file integrity monitoring; SDLC-developed solutions; digital signature; code review and pentest."},
    {"aspect": "Availability", "code": "A1", "label": "Best effort", "criteria": "No protection, since availability is not time critical", "business_impact": "The data can be unavailable for a longer period of time without consequences. No consequential damage.", "controls": "No special measures to avoid abnormal interruptions are needed. Recovery can wait until after prioritized solutions are handled.", "example_assets": "Network equipment; backup copies; application software; shipment information; banking transactions; customer payments; system documentation; job schedule; e-mail."},
    {"aspect": "Availability", "code": "A2 (SL3)", "label": "Retrievable", "criteria": "Information must be retrievable within reasonable time. Short interruptions are accepted", "business_impact": "The data or service may fail occasionally. Incidental downtime is allowed. Continuity should resume within a reasonable period. Unavailability can cause some direct or indirect damage.", "controls": "Only basic measures to prohibit users from causing interruptions are required. Controls detect downtime and trigger an alarm if an interruption occurs."},
    {"aspect": "Availability", "code": "A3 (SL2)", "label": "Trustworthy", "criteria": "Information must be restored immediately. Planned and agreed interruptions are accepted", "business_impact": "The data or service should almost never fail. Hardly any downtime is allowed. Continuity should resume soon. Unavailability can cause serious direct or indirect damage.", "controls": "Interruptions planned in advance; controls prohibit users from causing interruptions; controls detect downtime and trigger an alarm; SDLC-developed solutions; pentests conducted."},
    {"aspect": "Availability", "code": "A4 (SL1)", "label": "Instant access", "criteria": "The information requires instant access. Unplanned interruptions would cause severe damage", "business_impact": "Downtime is only allowed in very exceptional circumstances (e.g. calamity). The critical business process does not allow any downtime. Continuity must resume very quickly. Unavailability can inflict (very) extensive damage.", "controls": "Time critical windows identified; interruptions planned and agreed in advance; controls deny unwanted access and prohibit damage/interruptions; SDLC-developed solutions; redundancy to minimize unavailability; immediate actions in case of unavailability; pentests conducted."},
]

INFORMATION_ASSETS = [
    {"domain": "Market & Customer", "asset": "Customer Personal Data", "definition": "Personal data is data which can be used to identify a living individual (direct identification) or data which can be used along with other information in our possession, or likely to come into our possession, to identify an individual (indirect identification). Not limited to structured data -- can include images, video/call recordings, blog posts or opinions, IP addresses and cookie files.", "suggested_confidentiality": "Internal, confidential or strictly confidential (depending on context)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Market & Customer", "asset": "Sensitive Customer Personal Data", "definition": "Personal data consisting of health, philosophical and religious beliefs, political opinions, race or ethnic origin, sexual life, personal identity numbers, genetic and biometric data, payment card data, online tracking data, geo-location, or data relating to an individual's wealth.", "suggested_confidentiality": "Confidential or strictly confidential (depending on volume)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Market & Customer", "asset": "Marketing", "definition": "Information related to campaigns, competitors, catalogue, commercial activities.", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Market & Customer", "asset": "Card Transaction Information", "definition": "Information regarding customer card transactions -- transaction amount, date, location -- but not card data.", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Market & Customer", "asset": "Cardholder data", "definition": "Primary account number (card number), cardholder name, service code and expiration date (as defined in the PCI DSS standard).", "suggested_confidentiality": "Confidential or strictly confidential (depending on volume)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Market & Customer", "asset": "Sensitive Authentication Data", "definition": "Information required to authenticate a card transaction, including full track data (magnetic-stripe or chip data), CAV2/CVC2/CVV2/CID, PINs/PIN blocks, and cryptographic keys used to protect that data.", "suggested_confidentiality": "Strictly confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Co-worker", "asset": "Co-worker Personal Data", "definition": "Personal data which can be used to identify a co-worker (direct or indirect identification). Not limited to structured data.", "suggested_confidentiality": "Internal, confidential or strictly confidential (depending on context)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Co-worker", "asset": "Sensitive co-worker Personal Data", "definition": "Personal data consisting of health (physical/mental), philosophical/religious beliefs, political opinions, sexual life, race or ethnic origin, trade union membership, personal identity numbers, genetic/biometric data, criminal convictions, online tracking outside the organization's domain, geo-location, salary/wealth data, performance data, or grievance/disciplinary data.", "suggested_confidentiality": "Confidential or strictly confidential (depending on volume)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Direction", "asset": "Strategies and strategical business information", "definition": "Includes expansion plans, new markets, strategic sales information, cost of production, price models.", "suggested_confidentiality": "Confidential or strictly confidential (depending on sensitivity)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Direction", "asset": "Short-term corporate secrets", "definition": "Projects or programs such as R&D projects (early phases), acquisitions, complex negotiations, site closures/openings, sensitive-area work, redundancy or reorganizational programs.", "suggested_confidentiality": "Strictly confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Treasury", "asset": "Trading information", "definition": "Treasury related information, including liquidity, investments and financial transactions.", "suggested_confidentiality": "Strictly confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Information technology", "asset": "Security incident reporting", "definition": "Information related to security incidents or other major incidents within the organization or with third parties.", "suggested_confidentiality": "Internal or confidential (depending on sensitivity)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Range and product", "asset": "Range and product information", "definition": "Information related to the lifecycle of the range and products, from requirement, development and manufacturing to the selling perspective.", "suggested_confidentiality": "Public, internal or confidential depending on the lifecycle phase", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Supply and manufacture", "asset": "Supply and manufacture information", "definition": "Information related to supply chain and manufacturing, covering both products and services.", "suggested_confidentiality": "Public, internal or confidential (depending on sensitivity)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Supply and manufacture", "asset": "Contracts and agreements", "definition": "All information connected to contracts and third party agreements, including tenders, supplier relationships, scores, prices.", "suggested_confidentiality": "Internal, confidential or strictly confidential (depending on sensitivity)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Property", "asset": "Property information", "definition": "Entities and structures describing assets owned by or of interest to the business, and how they are used (buildings, machinery, cars, ground).", "suggested_confidentiality": "Confidential (depending on sensitivity)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Yearly financial summary", "definition": "", "suggested_confidentiality": "Public", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Product sales price", "definition": "", "suggested_confidentiality": "Public", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Weekly sales", "definition": "", "suggested_confidentiality": "Internal", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Purchase prices", "definition": "", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Financial salary calculation", "definition": "", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Management letter of the auditors", "definition": "", "suggested_confidentiality": "Strictly confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Draft statutory reports", "definition": "", "suggested_confidentiality": "Strictly confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Financial and accounting manual", "definition": "", "suggested_confidentiality": "Internal", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Finance", "asset": "Business impact assessment report", "definition": "", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Third-Party & ICT Risk", "asset": "ICT Third-Party Provider Register", "definition": "Register of contractual arrangements with ICT third-party service providers, including sub-outsourcing chains, criticality assessments and concentration-risk indicators (e.g. DORA).", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Third-Party & ICT Risk", "asset": "ICT & Cyber Incident Register", "definition": "Log of major ICT-related incidents, near misses and significant cyber threats, including classification, root-cause analysis and notifications made to supervisory authorities or national CSIRTs (NIS2/DORA incident-reporting obligations).", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Third-Party & ICT Risk", "asset": "Business Continuity & Resilience Testing Records", "definition": "Results of business continuity, disaster recovery and digital operational resilience testing, including threat-led penetration testing (TLPT) outcomes and remediation plans.", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Artificial Intelligence", "asset": "AI System Documentation & Training Data", "definition": "Technical documentation, risk classification, training/validation datasets and human-oversight records for AI systems, particularly high-risk systems under applicable AI regulation.", "suggested_confidentiality": "Confidential or strictly confidential (depending on training data sensitivity)", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Artificial Intelligence", "asset": "AI Model Outputs & Automated Decision Records", "definition": "Logs, outputs and explainability documentation for AI/ML-based automated decision-making or profiling, supporting transparency and human-review obligations.", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
    {"domain": "Law and regulations", "asset": "Regulatory Compliance Register", "definition": "Record of applicable legal and regulatory obligations (e.g. GDPR, NIS2, DORA, AI regulation), compliance assessments, audit findings and correspondence with supervisory authorities.", "suggested_confidentiality": "Confidential", "suggested_integrity": "", "suggested_availability": ""},
]

DEFAULT_CONFIG = {
    "org_name": DEFAULT_ORG_NAME,
    "settings": DEFAULT_SETTINGS,
    "option_lists": OPTION_LISTS,
    "tools": {
        "bia": TOOL_BIA,
        "dpia0": TOOL_DPIA0,
        "dpia": TOOL_DPIA,
    },
    "impact_scale_table": IMPACT_SCALE_TABLE,
    "classification_matrix": CLASSIFICATION_MATRIX,
    "information_assets": INFORMATION_ASSETS,
}
