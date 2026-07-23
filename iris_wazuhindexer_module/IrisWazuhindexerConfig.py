#!/usr/bin/env python3
#
#
#  IRIS wazuhindexer Source Code
#  Copyright (C) 2026 - iris-wazuhindexer-module
#  hello@iris-wazuhindexer-module.com
#  Created by iris-wazuhindexer-module - 2026-07-23
#
#  License MIT

module_name = "IrisWazuhindexer"
module_description = ""
interface_version = 1.2
module_version = 1.1

pipeline_support = False
pipeline_info = {}


module_configuration = [
    {
        "param_name": "wazuhindexer_host",
        "param_human_name": "wazuhindexer Host",
        "param_description": "Hostname",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "wazuhindexer_port",
        "param_human_name": "wazuhindexer Port",
        "param_description": "Port number",
        "default": 9200,
        "mandatory": True,
        "type": "float"
    },
    {
        "param_name": "wazuhindexer_key",
        "param_human_name": "wazuhindexer API key",
        "param_description": "wazuhindexer API key",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "wazuhindexer_user",
        "param_human_name": "wazuhindexer User",
        "param_description": "",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "wazuhindexer_pass",
        "param_human_name": "Wazuh-Indexer Password",
        "param_description": "Set the Wazuh-Indexer password associated with your defined user to authenticate with",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "wazuhindexer_index",
        "param_human_name": "Wazuh-Indexer Index",
        "param_description": "Define the Wazuh-Indexer indices to use - wazuh-*",
        "default": None,
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_field_domain",
        "param_human_name": "Wazuh-Indexer Domain Field",
        "param_description": "Define the fields to query",
        "default": "dns_query",
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_field_ip",
        "param_human_name": "Wazuh-Indexer IP Field",
        "param_description": "Define the fields to query",
        "default": "dst_ip",
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_field_sha256",
        "param_human_name": "Wazuh-Indexer Sha256 Field",
        "param_description": "Define the fields to query",
        "default": "sha256",
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_field_fileName",
        "param_human_name": "Wazuh-Indexer File Name Field",
        "param_description": "Define the fields to query",
        "default": "data_win_eventdata_targetFilename",
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_size",
        "param_human_name": "Size",
        "param_description": "Define the number of hits per index to return",
        "default": "10",
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_http_compress",
        "param_human_name": "Enable gzip compression",
        "param_description": "Enables gzip compression",
        "default": True,
        "mandatory": False,
        "type": "bool"
    },
    {
        "param_name": "wazuhindexer_ssl",
        "param_human_name": "Verify SSL",
        "param_description": "Verify SSL certificate",
        "default": False,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "wazuhindexer_ca_cert",
        "param_human_name": "Wazuh-Indexer Root CA",
        "param_description": "Root CA Cert",
        "default": "/full/path/to/root-ca.pem",
        "mandatory": False,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_cert_path",
        "param_human_name": "Wazuh-Indexer Cert",
        "param_description": "Client Certificate Path",
        "default": "/full/path/to/client.pem",
        "mandatory": False,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_cert_key",
        "param_human_name": "Wazuh-Indexer Cert Key",
        "param_description": "Client Key Path",
        "default": "/full/path/to/client-key.pem",
        "mandatory": False,
        "type": "string"
    },
    {
        "param_name": "wazuhindexer_manual_hook_enabled",
        "param_human_name": "Manual triggers on IOCs",
        "param_description": "Set to True to offers possibility to manually triggers the module via the UI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "wazuhindexer_on_create_hook_enabled",
        "param_human_name": "Triggers automatically on IOC create",
        "param_description": "Set to True to automatically add a wazuhindexer insight each time an IOC is created",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "wazuhindexer_on_update_hook_enabled",
        "param_human_name": "Triggers automatically on IOC update",
        "param_description": "Set to True to automatically add a wazuhindexer insight each time an IOC is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "wazuhindexer_report_as_attribute",
        "param_human_name": "Add wazuhindexer report as new IOC attribute",
        "param_description": "Creates a new attribute on the IOC, base on the wazuhindexer report. Attributes are based "
                             "on the templates of this configuration",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },
    {
        "param_name": "wazuhindexer_ioc_report_template",
        "param_human_name": "Wazuh-Indexer Related IoCs report template",
        "param_description": "Wazuh-Indexer Related IoCs report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            <h2>Total Number of Hits {{ total_hits }}</h2>\n      <h3>Wazuh-Indexer raw results</h3>\n\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_r_wazuhindexer\" data-toggle=\"collapse\" data-target=\"#drop_raw_wazuhindexer\" aria-expanded=\"false\" aria-controls=\"drop_raw_wazuhindexer\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Raw Results\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_raw_wazuhindexer\" class=\"collapse\" aria-labelledby=\"drop_r_wazuhindexer\" style=\"\">\n                    <div class=\"card-body\">\n                        <div id='wazuhindexer_raw_ace'>{{ results| tojson(indent=4) }}</div>\n                    </div>\n                </div>\n            </div>\n        </div>\n    </div>\n</div> \n<script>\nvar wazuhindexer_in_raw = ace.edit(\"wazuhindexer_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: 30,\n});\nwazuhindexer_in_raw.setReadOnly(true);\nwazuhindexer_in_raw.setTheme(\"ace/theme/tomorrow\");\nwazuhindexer_in_raw.session.setMode(\"ace/mode/json\");\nwazuhindexer_in_raw.renderer.setShowGutter(true);\nwazuhindexer_in_raw.setOption(\"showLineNumbers\", true);\nwazuhindexer_in_raw.setOption(\"showPrintMargin\", false);\nwazuhindexer_in_raw.setOption(\"displayIndentGuides\", true);\nwazuhindexer_in_raw.setOption(\"maxLines\", \"Infinity\");\nwazuhindexer_in_raw.session.setUseWrapMode(true);\nwazuhindexer_in_raw.setOption(\"indentedSoftWrap\", true);\nwazuhindexer_in_raw.renderer.setScrollMargin(8, 5);\n</script> ",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    }
    
]