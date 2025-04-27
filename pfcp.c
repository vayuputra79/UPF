#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <semaphore.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <poll.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <resolv.h>

#include "pfcp.h"
#include "sirik_core.h"
#include "sirik_socket.h"




tlv_desc_t tlv_desc_more1 = { TLV_MORE, "More", 0, 1, 0, 0, { NULL } };
tlv_desc_t tlv_desc_more2 = { TLV_MORE, "More", 0, 2, 0, 0, { NULL } };
tlv_desc_t tlv_desc_more3 = { TLV_MORE, "More", 0, 3, 0, 0, { NULL } };
tlv_desc_t tlv_desc_more4 = { TLV_MORE, "More", 0, 4, 0, 0, { NULL } };
tlv_desc_t tlv_desc_more5 = { TLV_MORE, "More", 0, 5, 0, 0, { NULL } };
tlv_desc_t tlv_desc_more6 = { TLV_MORE, "More", 0, 6, 0, 0, { NULL } };
tlv_desc_t tlv_desc_more7 = { TLV_MORE, "More", 0, 7, 0, 0, { NULL } };
tlv_desc_t tlv_desc_more8 = { TLV_MORE, "More", 0, 8, 0, 0, { NULL } };


tlv_desc_t pfcp_tlv_desc_cause =
{
    TLV_UINT8,
    "Cause",
    PFCP_CAUSE_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_cause_t),
    { NULL }
};


tlv_desc_t pfcp_tlv_desc_source_interface =
{
    TLV_UINT8,
    "Source Interface",
    PFCP_SOURCE_INTERFACE_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_source_interface_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_f_teid =
{
    TLV_VAR_STR,
    "F-TEID",
    PFCP_F_TEID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_f_teid_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_network_instance =
{
    TLV_VAR_STR,
    "Network Instance",
    PFCP_NETWORK_INSTANCE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_network_instance_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_sdf_filter =
{
    TLV_VAR_STR,
    "SDF Filter",
    PFCP_SDF_FILTER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_sdf_filter_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_application_id =
{
    TLV_VAR_STR,
    "Application ID",
    PFCP_APPLICATION_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_application_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_gate_status =
{
    TLV_UINT8,
    "Gate Status",
    PFCP_GATE_STATUS_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_gate_status_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_mbr =
{
    TLV_VAR_STR,
    "MBR",
    PFCP_MBR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_mbr_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_gbr =
{
    TLV_VAR_STR,
    "GBR",
    PFCP_GBR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_gbr_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_qer_correlation_id =
{
    TLV_UINT32,
    "QER Correlation ID",
    PFCP_QER_CORRELATION_ID_TYPE,
    4,
    0,
    sizeof(pfcp_tlv_qer_correlation_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_precedence =
{
    TLV_UINT32,
    "Precedence",
    PFCP_PRECEDENCE_TYPE,
    4,
    0,
    sizeof(pfcp_tlv_precedence_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_transport_level_marking =
{
    TLV_VAR_STR,
    "Transport Level Marking",
    PFCP_TRANSPORT_LEVEL_MARKING_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_transport_level_marking_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_volume_threshold =
{
    TLV_VAR_STR,
    "Volume Threshold",
    PFCP_VOLUME_THRESHOLD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_volume_threshold_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_time_threshold =
{
    TLV_VAR_STR,
    "Time Threshold",
    PFCP_TIME_THRESHOLD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_time_threshold_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_monitoring_time =
{
    TLV_VAR_STR,
    "Monitoring Time",
    PFCP_MONITORING_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_monitoring_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_subsequent_volume_threshold =
{
    TLV_VAR_STR,
    "Subsequent Volume Threshold",
    PFCP_SUBSEQUENT_VOLUME_THRESHOLD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_subsequent_volume_threshold_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_subsequent_time_threshold =
{
    TLV_VAR_STR,
    "Subsequent Time Threshold",
    PFCP_SUBSEQUENT_TIME_THRESHOLD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_subsequent_time_threshold_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_inactivity_detection_time =
{
    TLV_VAR_STR,
    "Inactivity Detection Time",
    PFCP_INACTIVITY_DETECTION_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_inactivity_detection_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_reporting_triggers =
{
    TLV_UINT8,
    "Reporting Triggers",
    PFCP_REPORTING_TRIGGERS_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_reporting_triggers_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_redirect_information =
{
    TLV_VAR_STR,
    "Redirect Information",
    PFCP_REDIRECT_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_redirect_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_report_type =
{
    TLV_UINT8,
    "Report Type",
    PFCP_REPORT_TYPE_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_report_type_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_offending_ie =
{
    TLV_UINT16,
    "Offending IE",
    PFCP_OFFENDING_IE_TYPE,
    2,
    0,
    sizeof(pfcp_tlv_offending_ie_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_forwarding_policy =
{
    TLV_VAR_STR,
    "Forwarding Policy",
    PFCP_FORWARDING_POLICY_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_forwarding_policy_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_destination_interface =
{
    TLV_UINT8,
    "Destination Interface",
    PFCP_DESTINATION_INTERFACE_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_destination_interface_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_up_function_features =
{
    TLV_VAR_STR,
    "UP Function Features",
    PFCP_UP_FUNCTION_FEATURES_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_up_function_features_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_apply_action =
{
    TLV_UINT8,
    "Apply Action",
    PFCP_APPLY_ACTION_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_apply_action_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_downlink_data_service_information =
{
    TLV_VAR_STR,
    "Downlink Data Service Information",
    PFCP_DOWNLINK_DATA_SERVICE_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_downlink_data_service_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_downlink_data_notification_delay =
{
    TLV_VAR_STR,
    "Downlink Data Notification Delay",
    PFCP_DOWNLINK_DATA_NOTIFICATION_DELAY_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_downlink_data_notification_delay_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_dl_buffering_duration =
{
    TLV_VAR_STR,
    "DL Buffering Duration",
    PFCP_DL_BUFFERING_DURATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_dl_buffering_duration_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_dl_buffering_suggested_packet_count =
{
    TLV_VAR_STR,
    "DL Buffering Suggested Packet Count",
    PFCP_DL_BUFFERING_SUGGESTED_PACKET_COUNT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_dl_buffering_suggested_packet_count_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_pfcpsmreq_flags =
{
    TLV_UINT8,
    "PFCPSMReq-Flags",
    PFCP_PFCPSMREQ_FLAGS_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_pfcpsmreq_flags_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_pfcpsrrsp_flags =
{
    TLV_UINT8,
    "PFCPSRRsp-Flags",
    PFCP_PFCPSRRSP_FLAGS_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_pfcpsrrsp_flags_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_sequence_number =
{
    TLV_VAR_STR,
    "Sequence Number",
    PFCP_SEQUENCE_NUMBER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_sequence_number_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_metric =
{
    TLV_VAR_STR,
    "Metric",
    PFCP_METRIC_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_metric_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_timer =
{
    TLV_VAR_STR,
    "Timer",
    PFCP_TIMER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_timer_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_pdr_id =
{
    TLV_UINT16,
    "PDR ID",
    PFCP_PDR_ID_TYPE,
    2,
    0,
    sizeof(pfcp_tlv_pdr_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_f_seid =
{
    TLV_VAR_STR,
    "F-SEID",
    PFCP_F_SEID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_f_seid_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_node_id =
{
    TLV_VAR_STR,
    "Node ID",
    PFCP_NODE_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_node_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_pfd_contents =
{
    TLV_VAR_STR,
    "PFD contents",
    PFCP_PFD_CONTENTS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_pfd_contents_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_measurement_method =
{
    TLV_UINT8,
    "Measurement Method",
    PFCP_MEASUREMENT_METHOD_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_measurement_method_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_usage_report_trigger =
{
    TLV_VAR_STR,
    "Usage Report Trigger",
    PFCP_USAGE_REPORT_TRIGGER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_usage_report_trigger_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_measurement_period =
{
    TLV_VAR_STR,
    "Measurement Period",
    PFCP_MEASUREMENT_PERIOD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_measurement_period_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_fq_csid =
{
    TLV_VAR_STR,
    "FQ-CSID",
    PFCP_FQ_CSID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_fq_csid_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_volume_measurement =
{
    TLV_VAR_STR,
    "Volume Measurement",
    PFCP_VOLUME_MEASUREMENT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_volume_measurement_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_duration_measurement =
{
    TLV_VAR_STR,
    "Duration Measurement",
    PFCP_DURATION_MEASUREMENT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_duration_measurement_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_time_of_first_packet =
{
    TLV_VAR_STR,
    "Time of First Packet",
    PFCP_TIME_OF_FIRST_PACKET_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_time_of_first_packet_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_time_of_last_packet =
{
    TLV_VAR_STR,
    "Time of Last Packet",
    PFCP_TIME_OF_LAST_PACKET_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_time_of_last_packet_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_quota_holding_time =
{
    TLV_VAR_STR,
    "Quota Holding Time",
    PFCP_QUOTA_HOLDING_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_quota_holding_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_dropped_dl_traffic_threshold =
{
    TLV_VAR_STR,
    "Dropped DL Traffic Threshold",
    PFCP_DROPPED_DL_TRAFFIC_THRESHOLD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_dropped_dl_traffic_threshold_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_volume_quota =
{
    TLV_VAR_STR,
    "Volume Quota",
    PFCP_VOLUME_QUOTA_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_volume_quota_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_time_quota =
{
    TLV_VAR_STR,
    "Time Quota",
    PFCP_TIME_QUOTA_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_time_quota_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_start_time =
{
    TLV_VAR_STR,
    "Start Time",
    PFCP_START_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_start_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_end_time =
{
    TLV_VAR_STR,
    "End Time",
    PFCP_END_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_end_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_urr_id =
{
    TLV_UINT32,
    "URR ID",
    PFCP_URR_ID_TYPE,
    4,
    0,
    sizeof(pfcp_tlv_urr_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_linked_urr_id =
{
    TLV_VAR_STR,
    "Linked URR ID",
    PFCP_LINKED_URR_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_linked_urr_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_outer_header_creation =
{
    TLV_VAR_STR,
    "Outer Header Creation",
    PFCP_OUTER_HEADER_CREATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_outer_header_creation_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_bar_id =
{
    TLV_UINT8,
    "BAR ID",
    PFCP_BAR_ID_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_bar_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_cp_function_features =
{
    TLV_UINT8,
    "CP Function Features",
    PFCP_CP_FUNCTION_FEATURES_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_cp_function_features_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_usage_information =
{
    TLV_VAR_STR,
    "Usage Information",
    PFCP_USAGE_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_usage_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_application_instance_id =
{
    TLV_VAR_STR,
    "Application Instance ID",
    PFCP_APPLICATION_INSTANCE_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_application_instance_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_flow_information =
{
    TLV_VAR_STR,
    "Flow Information",
    PFCP_FLOW_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_flow_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ue_ip_address =
{
    TLV_VAR_STR,
    "UE IP Address",
    PFCP_UE_IP_ADDRESS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ue_ip_address_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_packet_rate =
{
    TLV_VAR_STR,
    "Packet Rate",
    PFCP_PACKET_RATE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_packet_rate_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_outer_header_removal =
{
    TLV_VAR_STR,
    "Outer Header Removal",
    PFCP_OUTER_HEADER_REMOVAL_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_outer_header_removal_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_recovery_time_stamp =
{
    TLV_UINT32,
    "Recovery Time Stamp",
    PFCP_RECOVERY_TIME_STAMP_TYPE,
    4,
    0,
    sizeof(pfcp_tlv_recovery_time_stamp_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_dl_flow_level_marking =
{
    TLV_VAR_STR,
    "DL Flow Level Marking",
    PFCP_DL_FLOW_LEVEL_MARKING_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_dl_flow_level_marking_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_header_enrichment =
{
    TLV_VAR_STR,
    "Header Enrichment",
    PFCP_HEADER_ENRICHMENT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_header_enrichment_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_measurement_information =
{
    TLV_VAR_STR,
    "Measurement Information",
    PFCP_MEASUREMENT_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_measurement_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_node_report_type =
{
    TLV_VAR_STR,
    "Node Report Type",
    PFCP_NODE_REPORT_TYPE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_node_report_type_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_remote_gtp_u_peer =
{
    TLV_VAR_STR,
    "Remote GTP-U Peer",
    PFCP_REMOTE_GTP_U_PEER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_remote_gtp_u_peer_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ur_seqn =
{
    TLV_VAR_STR,
    "UR-SEQN",
    PFCP_UR_SEQN_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ur_seqn_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_activate_predefined_rules =
{
    TLV_VAR_STR,
    "Activate Predefined Rules",
    PFCP_ACTIVATE_PREDEFINED_RULES_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_activate_predefined_rules_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_deactivate_predefined_rules =
{
    TLV_VAR_STR,
    "Deactivate Predefined Rules",
    PFCP_DEACTIVATE_PREDEFINED_RULES_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_deactivate_predefined_rules_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_far_id =
{
    TLV_UINT32,
    "FAR ID",
    PFCP_FAR_ID_TYPE,
    4,
    0,
    sizeof(pfcp_tlv_far_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_qer_id =
{
    TLV_UINT32,
    "QER ID",
    PFCP_QER_ID_TYPE,
    4,
    0,
    sizeof(pfcp_tlv_qer_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_oci_flags =
{
    TLV_VAR_STR,
    "OCI Flags",
    PFCP_OCI_FLAGS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_oci_flags_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_pfcp_association_release_request =
{
    TLV_VAR_STR,
    "PFCP Association Release Request",
    PFCP_PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_pfcp_association_release_request_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_graceful_release_period =
{
    TLV_VAR_STR,
    "Graceful Release Period",
    PFCP_GRACEFUL_RELEASE_PERIOD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_graceful_release_period_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_pdn_type =
{
    TLV_UINT8,
    "PDN Type",
    PFCP_PDN_TYPE_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_pdn_type_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_failed_rule_id =
{
    TLV_VAR_STR,
    "Failed Rule ID",
    PFCP_FAILED_RULE_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_failed_rule_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_time_quota_mechanism =
{
    TLV_VAR_STR,
    "Time Quota Mechanism",
    PFCP_TIME_QUOTA_MECHANISM_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_time_quota_mechanism_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_user_plane_ip_resource_information =
{
    TLV_VAR_STR,
    "User Plane IP Resource Information",
    PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_user_plane_ip_resource_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_user_plane_inactivity_timer =
{
    TLV_VAR_STR,
    "User Plane Inactivity Timer",
    PFCP_USER_PLANE_INACTIVITY_TIMER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_user_plane_inactivity_timer_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_aggregated_urrs =
{
    TLV_VAR_STR,
    "Aggregated URRs",
    PFCP_AGGREGATED_URRS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_aggregated_urrs_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_multiplier =
{
    TLV_VAR_STR,
    "Multiplier",
    PFCP_MULTIPLIER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_multiplier_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_aggregated_urr_id =
{
    TLV_VAR_STR,
    "Aggregated URR ID",
    PFCP_AGGREGATED_URR_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_aggregated_urr_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_subsequent_volume_quota =
{
    TLV_VAR_STR,
    "Subsequent Volume Quota",
    PFCP_SUBSEQUENT_VOLUME_QUOTA_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_subsequent_volume_quota_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_subsequent_time_quota =
{
    TLV_VAR_STR,
    "Subsequent Time Quota",
    PFCP_SUBSEQUENT_TIME_QUOTA_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_subsequent_time_quota_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_rqi =
{
    TLV_UINT8,
    "RQI",
    PFCP_RQI_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_rqi_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_qfi =
{
    TLV_UINT8,
    "QFI",
    PFCP_QFI_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_qfi_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_query_urr_reference =
{
    TLV_VAR_STR,
    "Query URR Reference",
    PFCP_QUERY_URR_REFERENCE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_query_urr_reference_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_additional_usage_reports_information =
{
    TLV_VAR_STR,
    "Additional Usage Reports Information",
    PFCP_ADDITIONAL_USAGE_REPORTS_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_additional_usage_reports_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_update_traffic_endpoint =
{
    TLV_VAR_STR,
    "Update Traffic Endpoint",
    PFCP_UPDATE_TRAFFIC_ENDPOINT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_traffic_endpoint_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_traffic_endpoint_id =
{
    TLV_VAR_STR,
    "Traffic Endpoint ID",
    PFCP_TRAFFIC_ENDPOINT_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_traffic_endpoint_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_mac_address =
{
    TLV_VAR_STR,
    "MAC address",
    PFCP_MAC_ADDRESS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_mac_address_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_c_tag =
{
    TLV_VAR_STR,
    "C-TAG",
    PFCP_C_TAG_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_c_tag_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_s_tag =
{
    TLV_VAR_STR,
    "S-TAG",
    PFCP_S_TAG_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_s_tag_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ethertype =
{
    TLV_VAR_STR,
    "Ethertype",
    PFCP_ETHERTYPE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ethertype_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_proxying =
{
    TLV_VAR_STR,
    "Proxying",
    PFCP_PROXYING_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_proxying_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ethernet_filter_id =
{
    TLV_VAR_STR,
    "Ethernet Filter ID",
    PFCP_ETHERNET_FILTER_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ethernet_filter_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ethernet_filter_properties =
{
    TLV_VAR_STR,
    "Ethernet Filter Properties",
    PFCP_ETHERNET_FILTER_PROPERTIES_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ethernet_filter_properties_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_suggested_buffering_packets_count =
{
    TLV_VAR_STR,
    "Suggested Buffering Packets Count",
    PFCP_SUGGESTED_BUFFERING_PACKETS_COUNT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_suggested_buffering_packets_count_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_user_id =
{
    TLV_VAR_STR,
    "User ID",
    PFCP_USER_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_user_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ethernet_pdu_session_information =
{
    TLV_VAR_STR,
    "Ethernet PDU Session Information",
    PFCP_ETHERNET_PDU_SESSION_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ethernet_pdu_session_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_mac_addresses_detected =
{
    TLV_VAR_STR,
    "MAC Addresses Detected",
    PFCP_MAC_ADDRESSES_DETECTED_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_mac_addresses_detected_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_mac_addresses_removed =
{
    TLV_VAR_STR,
    "MAC Addresses Removed",
    PFCP_MAC_ADDRESSES_REMOVED_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_mac_addresses_removed_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ethernet_inactivity_timer =
{
    TLV_VAR_STR,
    "Ethernet Inactivity Timer",
    PFCP_ETHERNET_INACTIVITY_TIMER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ethernet_inactivity_timer_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_additional_monitoring_time =
{
    TLV_VAR_STR,
    "Additional Monitoring Time",
    PFCP_ADDITIONAL_MONITORING_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_additional_monitoring_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_event_quota =
{
    TLV_VAR_STR,
    "Event Quota",
    PFCP_EVENT_QUOTA_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_event_quota_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_event_threshold =
{
    TLV_VAR_STR,
    "Event Threshold",
    PFCP_EVENT_THRESHOLD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_event_threshold_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_subsequent_event_quota =
{
    TLV_VAR_STR,
    "Subsequent Event Quota",
    PFCP_SUBSEQUENT_EVENT_QUOTA_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_subsequent_event_quota_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_subsequent_event_threshold =
{
    TLV_VAR_STR,
    "Subsequent Event Threshold",
    PFCP_SUBSEQUENT_EVENT_THRESHOLD_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_subsequent_event_threshold_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_trace_information =
{
    TLV_VAR_STR,
    "Trace Information",
    PFCP_TRACE_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_trace_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_framed_route =
{
    TLV_VAR_STR,
    "Framed-Route",
    PFCP_FRAMED_ROUTE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_framed_route_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_framed_routing =
{
    TLV_VAR_STR,
    "Framed-Routing",
    PFCP_FRAMED_ROUTING_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_framed_routing_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_framed_ipv6_route =
{
    TLV_VAR_STR,
    "Framed-IPv6-Route",
    PFCP_FRAMED_IPV6_ROUTE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_framed_ipv6_route_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_event_time_stamp =
{
    TLV_VAR_STR,
    "Event Time Stamp",
    PFCP_EVENT_TIME_STAMP_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_event_time_stamp_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_averaging_window =
{
    TLV_UINT32,
    "Averaging Window",
    PFCP_AVERAGING_WINDOW_TYPE,
    4,
    0,
    sizeof(pfcp_tlv_averaging_window_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_paging_policy_indicator =
{
    TLV_UINT8,
    "Paging Policy Indicator",
    PFCP_PAGING_POLICY_INDICATOR_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_paging_policy_indicator_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_apn_dnn =
{
    TLV_VAR_STR,
    "APN/DNN",
    PFCP_APN_DNN_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_apn_dnn_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc__interface_type =
{
    TLV_VAR_STR,
    "3GPP Interface Type",
    PFCP__INTERFACE_TYPE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv__interface_type_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_pfcpsrreq_flags =
{
    TLV_UINT8,
    "PFCPSRReq-Flags",
    PFCP_PFCPSRREQ_FLAGS_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_pfcpsrreq_flags_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_pfcpaureq_flags =
{
    TLV_UINT8,
    "PFCPAUReq-Flags",
    PFCP_PFCPAUREQ_FLAGS_TYPE,
    1,
    0,
    sizeof(pfcp_tlv_pfcpaureq_flags_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_activation_time =
{
    TLV_VAR_STR,
    "Activation Time",
    PFCP_ACTIVATION_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_activation_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_deactivation_time =
{
    TLV_VAR_STR,
    "Deactivation Time",
    PFCP_DEACTIVATION_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_deactivation_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_mar_id =
{
    TLV_VAR_STR,
    "MAR ID",
    PFCP_MAR_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_mar_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_steering_functionality =
{
    TLV_VAR_STR,
    "Steering Functionality",
    PFCP_STEERING_FUNCTIONALITY_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_steering_functionality_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_steering_mode =
{
    TLV_VAR_STR,
    "Steering Mode",
    PFCP_STEERING_MODE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_steering_mode_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_weight =
{
    TLV_VAR_STR,
    "Weight",
    PFCP_WEIGHT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_weight_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_priority =
{
    TLV_VAR_STR,
    "Priority",
    PFCP_PRIORITY_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_priority_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ue_ip_address_pool_identity =
{
    TLV_VAR_STR,
    "UE IP address Pool Identity",
    PFCP_UE_IP_ADDRESS_POOL_IDENTITY_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ue_ip_address_pool_identity_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_alternative_smf_ip_address =
{
    TLV_VAR_STR,
    "Alternative SMF IP Address",
    PFCP_ALTERNATIVE_SMF_IP_ADDRESS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_alternative_smf_ip_address_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_packet_replication_and_detection_carry_on_information =
{
    TLV_VAR_STR,
    "Packet Replication and Detection Carry-On Information",
    PFCP_PACKET_REPLICATION_AND_DETECTION_CARRY_ON_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_packet_replication_and_detection_carry_on_information_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_smf_set_id =
{
    TLV_VAR_STR,
    "SMF Set ID",
    PFCP_SMF_SET_ID_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_smf_set_id_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_quota_validity_time =
{
    TLV_VAR_STR,
    "Quota Validity Time",
    PFCP_QUOTA_VALIDITY_TIME_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_quota_validity_time_t),
    { NULL }
};

tlv_desc_t pfcp_tlv_desc_ethernet_packet_filter =
{
    TLV_COMPOUND,
    "Ethernet Packet Filter",
    PFCP_ETHERNET_PACKET_FILTER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ethernet_packet_filter_t),
    {
        &pfcp_tlv_desc_ethernet_filter_id,
        &pfcp_tlv_desc_ethernet_filter_properties,
        &pfcp_tlv_desc_mac_address,
        &pfcp_tlv_desc_ethertype,
        &pfcp_tlv_desc_c_tag,
        &pfcp_tlv_desc_s_tag,
        &pfcp_tlv_desc_sdf_filter,
        &tlv_desc_more8,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_pdi =
{
    TLV_COMPOUND,
    "PDI",
    PFCP_PDI_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_pdi_t),
    {
        &pfcp_tlv_desc_source_interface,
        &pfcp_tlv_desc_f_teid,
        &pfcp_tlv_desc_network_instance,
        &pfcp_tlv_desc_ue_ip_address,
        &pfcp_tlv_desc_traffic_endpoint_id,
        &pfcp_tlv_desc_sdf_filter,
        &tlv_desc_more8,
        &pfcp_tlv_desc_application_id,
        &pfcp_tlv_desc_ethernet_pdu_session_information,
        &pfcp_tlv_desc_ethernet_packet_filter,
        &pfcp_tlv_desc_qfi,
        &pfcp_tlv_desc_framed_route,
        &pfcp_tlv_desc_framed_routing,
        &pfcp_tlv_desc_framed_ipv6_route,
        &pfcp_tlv_desc__interface_type,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_create_pdr =
{
    TLV_COMPOUND,
    "Create PDR",
    PFCP_CREATE_PDR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_create_pdr_t),
    {
        &pfcp_tlv_desc_pdr_id,
        &pfcp_tlv_desc_precedence,
        &pfcp_tlv_desc_pdi,
        &pfcp_tlv_desc_outer_header_removal,
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_urr_id,
        &pfcp_tlv_desc_qer_id,
        &pfcp_tlv_desc_activate_predefined_rules,
        &pfcp_tlv_desc_activation_time,
        &pfcp_tlv_desc_deactivation_time,
        &pfcp_tlv_desc_mar_id,
        &pfcp_tlv_desc_packet_replication_and_detection_carry_on_information,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_forwarding_parameters =
{
    TLV_COMPOUND,
    "Forwarding Parameters",
    PFCP_FORWARDING_PARAMETERS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_forwarding_parameters_t),
    {
        &pfcp_tlv_desc_destination_interface,
        &pfcp_tlv_desc_network_instance,
        &pfcp_tlv_desc_redirect_information,
        &pfcp_tlv_desc_outer_header_creation,
        &pfcp_tlv_desc_transport_level_marking,
        &pfcp_tlv_desc_forwarding_policy,
        &pfcp_tlv_desc_header_enrichment,
        &pfcp_tlv_desc_traffic_endpoint_id,
        &pfcp_tlv_desc_proxying,
        &pfcp_tlv_desc__interface_type,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_duplicating_parameters =
{
    TLV_COMPOUND,
    "Duplicating Parameters",
    PFCP_DUPLICATING_PARAMETERS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_duplicating_parameters_t),
    {
        &pfcp_tlv_desc_destination_interface,
        &pfcp_tlv_desc_outer_header_creation,
        &pfcp_tlv_desc_transport_level_marking,
        &pfcp_tlv_desc_forwarding_policy,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_create_far =
{
    TLV_COMPOUND,
    "Create FAR",
    PFCP_CREATE_FAR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_create_far_t),
    {
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_apply_action,
        &pfcp_tlv_desc_forwarding_parameters,
        &pfcp_tlv_desc_duplicating_parameters,
        &pfcp_tlv_desc_bar_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_forwarding_parameters =
{
    TLV_COMPOUND,
    "Update Forwarding Parameters",
    PFCP_UPDATE_FORWARDING_PARAMETERS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_forwarding_parameters_t),
    {
        &pfcp_tlv_desc_destination_interface,
        &pfcp_tlv_desc_network_instance,
        &pfcp_tlv_desc_redirect_information,
        &pfcp_tlv_desc_outer_header_creation,
        &pfcp_tlv_desc_transport_level_marking,
        &pfcp_tlv_desc_forwarding_policy,
        &pfcp_tlv_desc_header_enrichment,
        &pfcp_tlv_desc_pfcpsmreq_flags,
        &pfcp_tlv_desc_traffic_endpoint_id,
        &pfcp_tlv_desc__interface_type,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_duplicating_parameters =
{
    TLV_COMPOUND,
    "Update Duplicating Parameters",
    PFCP_UPDATE_DUPLICATING_PARAMETERS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_duplicating_parameters_t),
    {
        &pfcp_tlv_desc_destination_interface,
        &pfcp_tlv_desc_outer_header_creation,
        &pfcp_tlv_desc_transport_level_marking,
        &pfcp_tlv_desc_forwarding_policy,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_far =
{
    TLV_COMPOUND,
    "Update FAR",
    PFCP_UPDATE_FAR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_far_t),
    {
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_apply_action,
        &pfcp_tlv_desc_update_forwarding_parameters,
        &pfcp_tlv_desc_update_duplicating_parameters,
        &pfcp_tlv_desc_bar_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_pfd_context =
{
    TLV_COMPOUND,
    "PFD context",
    PFCP_PFD_CONTEXT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_pfd_context_t),
    {
        &pfcp_tlv_desc_pfd_contents,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_application_id_s_pfds =
{
    TLV_COMPOUND,
    "Application ID's PFDs",
    PFCP_APPLICATION_ID_S_PFDS_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_application_id_s_pfds_t),
    {
        &pfcp_tlv_desc_application_id,
        &pfcp_tlv_desc_pfd_context,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_ethernet_traffic_information =
{
    TLV_COMPOUND,
    "Ethernet Traffic Information",
    PFCP_ETHERNET_TRAFFIC_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_ethernet_traffic_information_t),
    {
        &pfcp_tlv_desc_mac_addresses_detected,
        &pfcp_tlv_desc_mac_addresses_removed,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_access_forwarding_action_information_1 =
{
    TLV_COMPOUND,
    "Access Forwarding Action Information 1",
    PFCP_ACCESS_FORWARDING_ACTION_INFORMATION_1_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_access_forwarding_action_information_1_t),
    {
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_weight,
        &pfcp_tlv_desc_priority,
        &pfcp_tlv_desc_urr_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_access_forwarding_action_information_2 =
{
    TLV_COMPOUND,
    "Access Forwarding Action Information 2",
    PFCP_ACCESS_FORWARDING_ACTION_INFORMATION_2_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_access_forwarding_action_information_2_t),
    {
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_weight,
        &pfcp_tlv_desc_priority,
        &pfcp_tlv_desc_urr_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_access_forwarding_action_information_1 =
{
    TLV_COMPOUND,
    "Update Access Forwarding Action Information 1",
    PFCP_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_1_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_access_forwarding_action_information_1_t),
    {
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_weight,
        &pfcp_tlv_desc_priority,
        &pfcp_tlv_desc_urr_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_access_forwarding_action_information_2 =
{
    TLV_COMPOUND,
    "Update Access Forwarding Action Information 2",
    PFCP_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_2_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_access_forwarding_action_information_2_t),
    {
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_weight,
        &pfcp_tlv_desc_priority,
        &pfcp_tlv_desc_urr_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_create_urr =
{
    TLV_COMPOUND,
    "Create URR",
    PFCP_CREATE_URR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_create_urr_t),
    {
        &pfcp_tlv_desc_urr_id,
        &pfcp_tlv_desc_measurement_method,
        &pfcp_tlv_desc_reporting_triggers,
        &pfcp_tlv_desc_measurement_period,
        &pfcp_tlv_desc_volume_threshold,
        &pfcp_tlv_desc_volume_quota,
        &pfcp_tlv_desc_event_threshold,
        &pfcp_tlv_desc_event_quota,
        &pfcp_tlv_desc_time_threshold,
        &pfcp_tlv_desc_time_quota,
        &pfcp_tlv_desc_quota_holding_time,
        &pfcp_tlv_desc_dropped_dl_traffic_threshold,
        &pfcp_tlv_desc_quota_validity_time,
        &pfcp_tlv_desc_monitoring_time,
        &pfcp_tlv_desc_subsequent_volume_threshold,
        &pfcp_tlv_desc_subsequent_time_threshold,
        &pfcp_tlv_desc_subsequent_volume_quota,
        &pfcp_tlv_desc_subsequent_time_quota,
        &pfcp_tlv_desc_subsequent_event_threshold,
        &pfcp_tlv_desc_subsequent_event_quota,
        &pfcp_tlv_desc_inactivity_detection_time,
        &pfcp_tlv_desc_linked_urr_id,
        &pfcp_tlv_desc_measurement_information,
        &pfcp_tlv_desc_time_quota_mechanism,
        &pfcp_tlv_desc_aggregated_urrs,
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_ethernet_inactivity_timer,
        &pfcp_tlv_desc_additional_monitoring_time,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_create_qer =
{
    TLV_COMPOUND,
    "Create QER",
    PFCP_CREATE_QER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_create_qer_t),
    {
        &pfcp_tlv_desc_qer_id,
        &pfcp_tlv_desc_qer_correlation_id,
        &pfcp_tlv_desc_gate_status,
        &pfcp_tlv_desc_mbr,
        &pfcp_tlv_desc_gbr,
        &pfcp_tlv_desc_packet_rate,
        &pfcp_tlv_desc_dl_flow_level_marking,
        &pfcp_tlv_desc_qfi,
        &pfcp_tlv_desc_rqi,
        &pfcp_tlv_desc_paging_policy_indicator,
        &pfcp_tlv_desc_averaging_window,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_created_pdr =
{
    TLV_COMPOUND,
    "Created PDR",
    PFCP_CREATED_PDR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_created_pdr_t),
    {
        &pfcp_tlv_desc_pdr_id,
        &pfcp_tlv_desc_f_teid,
        &pfcp_tlv_desc_ue_ip_address,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_pdr =
{
    TLV_COMPOUND,
    "Update PDR",
    PFCP_UPDATE_PDR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_pdr_t),
    {
        &pfcp_tlv_desc_pdr_id,
        &pfcp_tlv_desc_outer_header_removal,
        &pfcp_tlv_desc_precedence,
        &pfcp_tlv_desc_pdi,
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_urr_id,
        &pfcp_tlv_desc_qer_id,
        &pfcp_tlv_desc_activate_predefined_rules,
        &pfcp_tlv_desc_deactivate_predefined_rules,
        &pfcp_tlv_desc_activation_time,
        &pfcp_tlv_desc_deactivation_time,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_bar_pfcp_session_report_response =
{
    TLV_COMPOUND,
    "Update BAR PFCP Session Report Response",
    PFCP_UPDATE_BAR_PFCP_SESSION_REPORT_RESPONSE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_bar_pfcp_session_report_response_t),
    {
        &pfcp_tlv_desc_bar_id,
        &pfcp_tlv_desc_downlink_data_notification_delay,
        &pfcp_tlv_desc_dl_buffering_duration,
        &pfcp_tlv_desc_dl_buffering_suggested_packet_count,
        &pfcp_tlv_desc_suggested_buffering_packets_count,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_urr =
{
    TLV_COMPOUND,
    "Update URR",
    PFCP_UPDATE_URR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_urr_t),
    {
        &pfcp_tlv_desc_urr_id,
        &pfcp_tlv_desc_measurement_method,
        &pfcp_tlv_desc_reporting_triggers,
        &pfcp_tlv_desc_measurement_period,
        &pfcp_tlv_desc_volume_threshold,
        &pfcp_tlv_desc_volume_quota,
        &pfcp_tlv_desc_time_threshold,
        &pfcp_tlv_desc_time_quota,
        &pfcp_tlv_desc_event_threshold,
        &pfcp_tlv_desc_event_quota,
        &pfcp_tlv_desc_quota_holding_time,
        &pfcp_tlv_desc_dropped_dl_traffic_threshold,
        &pfcp_tlv_desc_quota_validity_time,
        &pfcp_tlv_desc_monitoring_time,
        &pfcp_tlv_desc_subsequent_volume_threshold,
        &pfcp_tlv_desc_subsequent_time_threshold,
        &pfcp_tlv_desc_subsequent_volume_quota,
        &pfcp_tlv_desc_subsequent_time_quota,
        &pfcp_tlv_desc_subsequent_event_threshold,
        &pfcp_tlv_desc_subsequent_event_quota,
        &pfcp_tlv_desc_inactivity_detection_time,
        &pfcp_tlv_desc_linked_urr_id,
        &pfcp_tlv_desc_measurement_information,
        &pfcp_tlv_desc_time_quota_mechanism,
        &pfcp_tlv_desc_aggregated_urrs,
        &pfcp_tlv_desc_far_id,
        &pfcp_tlv_desc_ethernet_inactivity_timer,
        &pfcp_tlv_desc_additional_monitoring_time,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_qer =
{
    TLV_COMPOUND,
    "Update QER",
    PFCP_UPDATE_QER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_qer_t),
    {
        &pfcp_tlv_desc_qer_id,
        &pfcp_tlv_desc_qer_correlation_id,
        &pfcp_tlv_desc_gate_status,
        &pfcp_tlv_desc_mbr,
        &pfcp_tlv_desc_gbr,
        &pfcp_tlv_desc_packet_rate,
        &pfcp_tlv_desc_dl_flow_level_marking,
        &pfcp_tlv_desc_qfi,
        &pfcp_tlv_desc_rqi,
        &pfcp_tlv_desc_paging_policy_indicator,
        &pfcp_tlv_desc_averaging_window,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_remove_pdr =
{
    TLV_COMPOUND,
    "Remove PDR",
    PFCP_REMOVE_PDR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_remove_pdr_t),
    {
        &pfcp_tlv_desc_pdr_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_remove_far =
{
    TLV_COMPOUND,
    "Remove FAR",
    PFCP_REMOVE_FAR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_remove_far_t),
    {
        &pfcp_tlv_desc_far_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_remove_urr =
{
    TLV_COMPOUND,
    "Remove URR",
    PFCP_REMOVE_URR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_remove_urr_t),
    {
        &pfcp_tlv_desc_urr_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_remove_qer =
{
    TLV_COMPOUND,
    "Remove QER",
    PFCP_REMOVE_QER_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_remove_qer_t),
    {
        &pfcp_tlv_desc_qer_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_load_control_information =
{
    TLV_COMPOUND,
    "Load Control Information",
    PFCP_LOAD_CONTROL_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_load_control_information_t),
    {
        &pfcp_tlv_desc_sequence_number,
        &pfcp_tlv_desc_metric,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_overload_control_information =
{
    TLV_COMPOUND,
    "Overload Control Information",
    PFCP_OVERLOAD_CONTROL_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_overload_control_information_t),
    {
        &pfcp_tlv_desc_sequence_number,
        &pfcp_tlv_desc_metric,
        &pfcp_tlv_desc_timer,
        &pfcp_tlv_desc_oci_flags,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_application_detection_information =
{
    TLV_COMPOUND,
    "Application Detection Information",
    PFCP_APPLICATION_DETECTION_INFORMATION_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_application_detection_information_t),
    {
        &pfcp_tlv_desc_application_id,
        &pfcp_tlv_desc_application_instance_id,
        &pfcp_tlv_desc_flow_information,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_query_urr =
{
    TLV_COMPOUND,
    "Query URR",
    PFCP_QUERY_URR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_query_urr_t),
    {
        &pfcp_tlv_desc_urr_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_usage_report_session_modification_response =
{
    TLV_COMPOUND,
    "Usage Report Session Modification Response",
    PFCP_USAGE_REPORT_SESSION_MODIFICATION_RESPONSE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_usage_report_session_modification_response_t),
    {
        &pfcp_tlv_desc_urr_id,
        &pfcp_tlv_desc_ur_seqn,
        &pfcp_tlv_desc_usage_report_trigger,
        &pfcp_tlv_desc_start_time,
        &pfcp_tlv_desc_end_time,
        &pfcp_tlv_desc_volume_measurement,
        &pfcp_tlv_desc_duration_measurement,
        &pfcp_tlv_desc_time_of_first_packet,
        &pfcp_tlv_desc_time_of_last_packet,
        &pfcp_tlv_desc_usage_information,
        &pfcp_tlv_desc_query_urr_reference,
        &pfcp_tlv_desc_ethernet_traffic_information,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_usage_report_session_deletion_response =
{
    TLV_COMPOUND,
    "Usage Report Session Deletion Response",
    PFCP_USAGE_REPORT_SESSION_DELETION_RESPONSE_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_usage_report_session_deletion_response_t),
    {
        &pfcp_tlv_desc_urr_id,
        &pfcp_tlv_desc_ur_seqn,
        &pfcp_tlv_desc_usage_report_trigger,
        &pfcp_tlv_desc_start_time,
        &pfcp_tlv_desc_end_time,
        &pfcp_tlv_desc_volume_measurement,
        &pfcp_tlv_desc_duration_measurement,
        &pfcp_tlv_desc_time_of_first_packet,
        &pfcp_tlv_desc_time_of_last_packet,
        &pfcp_tlv_desc_usage_information,
        &pfcp_tlv_desc_ethernet_traffic_information,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_usage_report_session_report_request =
{
    TLV_COMPOUND,
    "Usage Report Session Report Request",
    PFCP_USAGE_REPORT_SESSION_REPORT_REQUEST_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_usage_report_session_report_request_t),
    {
        &pfcp_tlv_desc_urr_id,
        &pfcp_tlv_desc_ur_seqn,
        &pfcp_tlv_desc_usage_report_trigger,
        &pfcp_tlv_desc_start_time,
        &pfcp_tlv_desc_end_time,
        &pfcp_tlv_desc_volume_measurement,
        &pfcp_tlv_desc_duration_measurement,
        &pfcp_tlv_desc_application_detection_information,
        &pfcp_tlv_desc_ue_ip_address,
        &pfcp_tlv_desc_network_instance,
        &pfcp_tlv_desc_time_of_first_packet,
        &pfcp_tlv_desc_time_of_last_packet,
        &pfcp_tlv_desc_usage_information,
        &pfcp_tlv_desc_query_urr_reference,
        &pfcp_tlv_desc_event_time_stamp,
        &pfcp_tlv_desc_ethernet_traffic_information,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_downlink_data_report =
{
    TLV_COMPOUND,
    "Downlink Data Report",
    PFCP_DOWNLINK_DATA_REPORT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_downlink_data_report_t),
    {
        &pfcp_tlv_desc_pdr_id,
        &pfcp_tlv_desc_downlink_data_service_information,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_create_bar =
{
    TLV_COMPOUND,
    "Create BAR",
    PFCP_CREATE_BAR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_create_bar_t),
    {
        &pfcp_tlv_desc_bar_id,
        &pfcp_tlv_desc_downlink_data_notification_delay,
        &pfcp_tlv_desc_suggested_buffering_packets_count,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_bar_session_modification_request =
{
    TLV_COMPOUND,
    "Update BAR Session Modification Request",
    PFCP_UPDATE_BAR_SESSION_MODIFICATION_REQUEST_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_bar_session_modification_request_t),
    {
        &pfcp_tlv_desc_bar_id,
        &pfcp_tlv_desc_downlink_data_notification_delay,
        &pfcp_tlv_desc_suggested_buffering_packets_count,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_remove_bar =
{
    TLV_COMPOUND,
    "Remove BAR",
    PFCP_REMOVE_BAR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_remove_bar_t),
    {
        &pfcp_tlv_desc_bar_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_error_indication_report =
{
    TLV_COMPOUND,
    "Error Indication Report",
    PFCP_ERROR_INDICATION_REPORT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_error_indication_report_t),
    {
        &pfcp_tlv_desc_f_teid,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_user_plane_path_failure_report =
{
    TLV_COMPOUND,
    "User Plane Path Failure Report",
    PFCP_USER_PLANE_PATH_FAILURE_REPORT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_user_plane_path_failure_report_t),
    {
        &pfcp_tlv_desc_remote_gtp_u_peer,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_create_traffic_endpoint =
{
    TLV_COMPOUND,
    "Create Traffic Endpoint",
    PFCP_CREATE_TRAFFIC_ENDPOINT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_create_traffic_endpoint_t),
    {
        &pfcp_tlv_desc_traffic_endpoint_id,
        &pfcp_tlv_desc_f_teid,
        &pfcp_tlv_desc_network_instance,
        &pfcp_tlv_desc_ue_ip_address,
        &pfcp_tlv_desc_ethernet_pdu_session_information,
        &pfcp_tlv_desc_framed_route,
        &pfcp_tlv_desc_framed_routing,
        &pfcp_tlv_desc_framed_ipv6_route,
        &pfcp_tlv_desc_qfi,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_created_traffic_endpoint =
{
    TLV_COMPOUND,
    "Created Traffic Endpoint",
    PFCP_CREATED_TRAFFIC_ENDPOINT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_created_traffic_endpoint_t),
    {
        &pfcp_tlv_desc_traffic_endpoint_id,
        &pfcp_tlv_desc_f_teid,
        &pfcp_tlv_desc_ue_ip_address,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_remove_traffic_endpoint =
{
    TLV_COMPOUND,
    "Remove Traffic Endpoint",
    PFCP_REMOVE_TRAFFIC_ENDPOINT_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_remove_traffic_endpoint_t),
    {
        &pfcp_tlv_desc_traffic_endpoint_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_create_mar =
{
    TLV_COMPOUND,
    "Create MAR",
    PFCP_CREATE_MAR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_create_mar_t),
    {
        &pfcp_tlv_desc_mar_id,
        &pfcp_tlv_desc_steering_functionality,
        &pfcp_tlv_desc_steering_mode,
        &pfcp_tlv_desc_access_forwarding_action_information_1,
        &pfcp_tlv_desc_access_forwarding_action_information_2,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_remove_mar =
{
    TLV_COMPOUND,
    "Remove MAR",
    PFCP_REMOVE_MAR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_remove_mar_t),
    {
        &pfcp_tlv_desc_mar_id,
        NULL,
    }
};

tlv_desc_t pfcp_tlv_desc_update_mar =
{
    TLV_COMPOUND,
    "Update MAR",
    PFCP_UPDATE_MAR_TYPE,
    0,
    0,
    sizeof(pfcp_tlv_update_mar_t),
    {
        &pfcp_tlv_desc_mar_id,
        &pfcp_tlv_desc_steering_functionality,
        &pfcp_tlv_desc_steering_mode,
        &pfcp_tlv_desc_update_access_forwarding_action_information_1,
        &pfcp_tlv_desc_update_access_forwarding_action_information_2,
        &pfcp_tlv_desc_access_forwarding_action_information_1,
        &pfcp_tlv_desc_access_forwarding_action_information_2,
        NULL,
    }
};

tlv_desc_t pfcp_msg_desc_pfcp_heartbeat_request =
{
    TLV_MESSAGE,
    "PFCP Heartbeat Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_recovery_time_stamp,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_heartbeat_response =
{
    TLV_MESSAGE,
    "PFCP Heartbeat Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_recovery_time_stamp,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_pfd_management_request =
{
    TLV_MESSAGE,
    "PFCP PFD Management Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_application_id_s_pfds,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_pfd_management_response =
{
    TLV_MESSAGE,
    "PFCP PFD Management Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_offending_ie,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_association_setup_request =
{
    TLV_MESSAGE,
    "PFCP Association Setup Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_recovery_time_stamp,
        &pfcp_tlv_desc_up_function_features,
        &pfcp_tlv_desc_cp_function_features,
        &pfcp_tlv_desc_user_plane_ip_resource_information,
        &tlv_desc_more4,
        &pfcp_tlv_desc_ue_ip_address,
        &pfcp_tlv_desc_alternative_smf_ip_address,
        &pfcp_tlv_desc_smf_set_id,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_association_setup_response =
{
    TLV_MESSAGE,
    "PFCP Association Setup Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_recovery_time_stamp,
        &pfcp_tlv_desc_up_function_features,
        &pfcp_tlv_desc_cp_function_features,
        &pfcp_tlv_desc_user_plane_ip_resource_information,
        &tlv_desc_more4,
        &pfcp_tlv_desc_alternative_smf_ip_address,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_association_update_request =
{
    TLV_MESSAGE,
    "PFCP Association Update Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_up_function_features,
        &pfcp_tlv_desc_cp_function_features,
        &pfcp_tlv_desc_pfcp_association_release_request,
        &pfcp_tlv_desc_graceful_release_period,
        &pfcp_tlv_desc_user_plane_ip_resource_information,
        &tlv_desc_more4,
        &pfcp_tlv_desc_pfcpaureq_flags,
        &pfcp_tlv_desc_alternative_smf_ip_address,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_association_update_response =
{
    TLV_MESSAGE,
    "PFCP Association Update Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_up_function_features,
        &pfcp_tlv_desc_cp_function_features,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_association_release_request =
{
    TLV_MESSAGE,
    "PFCP Association Release Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_association_release_response =
{
    TLV_MESSAGE,
    "PFCP Association Release Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_cause,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_version_not_supported_response =
{
    TLV_MESSAGE,
    "PFCP Version Not Supported Response",
    0, 0, 0, 0, {
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_node_report_request =
{
    TLV_MESSAGE,
    "PFCP Node Report Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_node_report_type,
        &pfcp_tlv_desc_user_plane_path_failure_report,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_node_report_response =
{
    TLV_MESSAGE,
    "PFCP Node Report Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_offending_ie,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_set_deletion_request =
{
    TLV_MESSAGE,
    "PFCP Session Set Deletion Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_set_deletion_response =
{
    TLV_MESSAGE,
    "PFCP Session Set Deletion Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_offending_ie,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_establishment_request =
{
    TLV_MESSAGE,
    "PFCP Session Establishment Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_f_seid,
        &pfcp_tlv_desc_create_pdr,
        &tlv_desc_more8,
        &pfcp_tlv_desc_create_far,
        &tlv_desc_more8,
        &pfcp_tlv_desc_create_urr,
        &tlv_desc_more2,
        &pfcp_tlv_desc_create_qer,
        &tlv_desc_more4,
        &pfcp_tlv_desc_create_bar,
        &pfcp_tlv_desc_create_traffic_endpoint,
        &pfcp_tlv_desc_pdn_type,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_user_plane_inactivity_timer,
        &pfcp_tlv_desc_user_id,
        &pfcp_tlv_desc_trace_information,
        &pfcp_tlv_desc_apn_dnn,
        &pfcp_tlv_desc_create_mar,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_establishment_response =
{
    TLV_MESSAGE,
    "PFCP Session Establishment Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_node_id,
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_offending_ie,
        &pfcp_tlv_desc_f_seid,
        &pfcp_tlv_desc_created_pdr,
        &tlv_desc_more8,
        &pfcp_tlv_desc_load_control_information,
        &pfcp_tlv_desc_overload_control_information,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_failed_rule_id,
        &pfcp_tlv_desc_created_traffic_endpoint,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_modification_request =
{
    TLV_MESSAGE,
    "PFCP Session Modification Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_f_seid,
        &pfcp_tlv_desc_remove_pdr,
        &tlv_desc_more8,
        &pfcp_tlv_desc_remove_far,
        &tlv_desc_more8,
        &pfcp_tlv_desc_remove_urr,
        &tlv_desc_more2,
        &pfcp_tlv_desc_remove_qer,
        &tlv_desc_more4,
        &pfcp_tlv_desc_remove_bar,
        &pfcp_tlv_desc_remove_traffic_endpoint,
        &pfcp_tlv_desc_create_pdr,
        &tlv_desc_more8,
        &pfcp_tlv_desc_create_far,
        &tlv_desc_more8,
        &pfcp_tlv_desc_create_urr,
        &tlv_desc_more2,
        &pfcp_tlv_desc_create_qer,
        &tlv_desc_more4,
        &pfcp_tlv_desc_create_bar,
        &pfcp_tlv_desc_create_traffic_endpoint,
        &pfcp_tlv_desc_update_pdr,
        &tlv_desc_more8,
        &pfcp_tlv_desc_update_far,
        &tlv_desc_more8,
        &pfcp_tlv_desc_update_urr,
        &tlv_desc_more2,
        &pfcp_tlv_desc_update_qer,
        &tlv_desc_more4,
        &pfcp_tlv_desc_update_bar_session_modification_request,
        &pfcp_tlv_desc_update_traffic_endpoint,
        &pfcp_tlv_desc_pfcpsmreq_flags,
        &pfcp_tlv_desc_query_urr,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_fq_csid,
        &pfcp_tlv_desc_user_plane_inactivity_timer,
        &pfcp_tlv_desc_query_urr_reference,
        &pfcp_tlv_desc_trace_information,
        &pfcp_tlv_desc_remove_mar,
        &pfcp_tlv_desc_update_mar,
        &pfcp_tlv_desc_create_mar,
        &pfcp_tlv_desc_node_id,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_modification_response =
{
    TLV_MESSAGE,
    "PFCP Session Modification Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_offending_ie,
        &pfcp_tlv_desc_created_pdr,
        &tlv_desc_more8,
        &pfcp_tlv_desc_load_control_information,
        &pfcp_tlv_desc_overload_control_information,
        &pfcp_tlv_desc_usage_report_session_modification_response,
        &pfcp_tlv_desc_failed_rule_id,
        &pfcp_tlv_desc_additional_usage_reports_information,
        &pfcp_tlv_desc_created_traffic_endpoint,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_deletion_request =
{
    TLV_MESSAGE,
    "PFCP Session Deletion Request",
    0, 0, 0, 0, {
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_deletion_response =
{
    TLV_MESSAGE,
    "PFCP Session Deletion Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_offending_ie,
        &pfcp_tlv_desc_load_control_information,
        &pfcp_tlv_desc_overload_control_information,
        &pfcp_tlv_desc_usage_report_session_deletion_response,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_report_request =
{
    TLV_MESSAGE,
    "PFCP Session Report Request",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_report_type,
        &pfcp_tlv_desc_downlink_data_report,
        &pfcp_tlv_desc_usage_report_session_report_request,
        &pfcp_tlv_desc_error_indication_report,
        &pfcp_tlv_desc_load_control_information,
        &pfcp_tlv_desc_overload_control_information,
        &pfcp_tlv_desc_additional_usage_reports_information,
        &pfcp_tlv_desc_pfcpsrreq_flags,
        &pfcp_tlv_desc_f_seid,
    NULL,
}};

tlv_desc_t pfcp_msg_desc_pfcp_session_report_response =
{
    TLV_MESSAGE,
    "PFCP Session Report Response",
    0, 0, 0, 0, {
        &pfcp_tlv_desc_cause,
        &pfcp_tlv_desc_offending_ie,
        &pfcp_tlv_desc_update_bar_pfcp_session_report_response,
        &pfcp_tlv_desc_pfcpsrrsp_flags,
        &pfcp_tlv_desc_f_seid,
        &pfcp_tlv_desc_f_teid,
        &pfcp_tlv_desc_alternative_smf_ip_address,
    NULL,
}};




si_sirik_pool_t * __pfcp_tlvPool = NULL;

void pfcp_message__init()
{
	__pfcp_tlvPool = __si_pool_create( "pfcp-tlv-pool", sizeof(tlv_t), 1000, 1);
}





tlv_t * tlv_get()
{
	tlv_t * tlv = (tlv_t *) __si_pool_allocate( __pfcp_tlvPool);
	memset( tlv, 0, sizeof(tlv_t));
	
	return tlv;
}

void tlv_free( tlv_t * tlv)
{
	__si_pool_release( (uint8_t*)tlv);
}


void tlv_free_all( tlv_t * root)
{
    tlv_t *iter = root;
    tlv_t *next = NULL;
	
    while (iter) 
	{
        if(iter->embedded != NULL) 
		{
            tlv_free_all( iter->embedded);
        }
        
		next = iter->next;
        tlv_free(iter);
        iter = next;
    }
}

uint32_t tlv_calc_length( tlv_t * tlv, uint8_t mode)
{
    tlv_t * iter = tlv;
    uint32_t length = 0;
	uint32_t prev_length = 0;
 
    while(iter) 
	{
        switch(mode) 
		{
			case TLV_MODE_T1_L1:
				length += 2;
				break;
			case TLV_MODE_T1_L2:
				length += 3;
				break;
			case TLV_MODE_T1_L2_I1:
			case TLV_MODE_T2_L2:
				length += 4;
				break;
			default:
				break;
        }


        if(iter->embedded != NULL) 
		{
            iter->length = tlv_calc_length( iter->embedded, mode);
        }
		

		prev_length = length;
		
        length += iter->length;
        iter = iter->next;
    }
	
    return length;
}

uint32_t tlv_calc_count( tlv_t * tlv)
{
    tlv_t * iter = tlv;
    uint32_t count = 0;

    while(iter) 
	{
        if(iter->embedded != NULL) 
		{
            count += tlv_calc_count( iter->embedded);
        } 
		else 
		{
            count++;
        }
        iter = iter->next;
    }
    return count;
}


uint8_t tlv_value_8( tlv_t * tlv)
{
    return (*((uint8_t*)(tlv->value)));
}

uint16_t tlv_value_16( tlv_t * tlv)
{
    uint16_t u_16;
    uint8_t *v = tlv->value;

    u_16 = ((v[0] <<  8) & 0xff00) |
           ((v[1]      ) & 0x00ff);

    return u_16;
}

uint32_t tlv_value_32( tlv_t *tlv)
{
    uint32_t u_32;
    uint8_t *v = tlv->value;

    u_32 = ((v[0] << 24) & 0xff000000) |
           ((v[1] << 16) & 0x00ff0000) |
           ((v[2] <<  8) & 0x0000ff00) |
           ((v[3]      ) & 0x000000ff);

    return u_32;
}



uint8_t * tlv_put_type( uint32_t type, uint8_t * pos, uint8_t mode)
{    
	switch(mode) 
	{
		case TLV_MODE_T1_L1:
		case TLV_MODE_T1_L2:
		case TLV_MODE_T1_L2_I1:
			*(pos++) = type & 0xFF;
			break;
		case TLV_MODE_T2_L2:
			*(pos++) = (type >> 8) & 0xFF;
			*(pos++) = type & 0xFF;
			break;
		default:
			break;
	}
	
	return pos;
}

uint8_t * tlv_put_length( uint32_t length, uint8_t * pos, uint8_t mode)
{
    switch(mode) 
	{
		case TLV_MODE_T1_L1:
			*(pos++) = length & 0xFF;
			break;
		case TLV_MODE_T1_L2:
		case TLV_MODE_T1_L2_I1:
		case TLV_MODE_T2_L2:
			*(pos++) = (length >> 8) & 0xFF;
			*(pos++) = length & 0xFF;
			break;
		default:
			break;
    }

    return pos;
}

uint8_t * tlv_put_instance( uint8_t instance, uint8_t * pos, uint8_t mode)
{
    switch(mode) 
	{
        case TLV_MODE_T1_L2_I1:
            *(pos++) = instance & 0xFF;
            break;
        default:
            break;
    }

    return pos;
}

uint8_t * tlv_get_element( tlv_t * tlv, uint8_t * blk, uint8_t mode)
{
	uint8_t * pos = blk;

	switch(mode) 
	{
		case TLV_MODE_T1_L1:
			tlv->type = *(pos++);
			tlv->length = *(pos++);
			break;
		case TLV_MODE_T1_L2:
			tlv->type = *(pos++);
			tlv->length = *(pos++) << 8;
			tlv->length += *(pos++);
			break;
		case TLV_MODE_T1_L2_I1:
			tlv->type = *(pos++);
			tlv->length = *(pos++) << 8;
			tlv->length += *(pos++);
			tlv->instance = *(pos++);
			break;
		case TLV_MODE_T2_L2:
			tlv->type = *(pos++) << 8;
			tlv->type += *(pos++);
			tlv->length = *(pos++) << 8;
			tlv->length += *(pos++);
			break;
		default:
			break;
	}

	tlv->value = pos;
	return ( pos + tlv_length( tlv));
}

void tlv_alloc_buff_to_tlv( tlv_t * head, uint8_t * buff, uint32_t buff_len)
{
    head->buff_allocated = 1;
    head->buff_len = buff_len;
    head->buff_ptr = buff;
    head->buff = buff;
}

tlv_t * tlv_find_root( tlv_t * tlv)
{
    tlv_t * head = tlv->head;
    tlv_t * parent;

    parent = head->parent;
    while(parent) 
	{
        head = parent->head;
        parent = head->parent;
    }

    return head;
}



tlv_t * tlv_add( tlv_t * head, uint32_t type, uint32_t length, uint8_t instance, void * value)
{
    tlv_t * curr = head;
    tlv_t * new = NULL;

    new = tlv_get();

    new->type = type;
    new->length = length;
    new->instance = instance;
    new->value = value;

    if ( head != NULL && head->buff_allocated == 1) 
	{
        memcpy( head->buff_ptr, value, length);
        new->value = head->buff_ptr;
        head->buff_ptr += length;
    }

    if(curr == NULL) 
	{
        new->head = new;
        new->tail = new;
    } 
	else 
	{
        head = head->head;
        new->head = head;
        head->tail->next = new;
        head->tail = new;
    }
	
    return new;
}

tlv_t * tlv_copy( void * buff, uint32_t buff_len, uint32_t type, uint32_t length, uint8_t instance, void * value)
{
    tlv_t * new = NULL;

    new = tlv_get();

    new->type = type;
    new->length = length;
    new->instance = instance;
    new->value = value;
    new->head = new->tail = new;

    tlv_alloc_buff_to_tlv( new, buff, buff_len);

    memcpy( new->buff_ptr, value, length);
    new->value = new->buff_ptr;
    new->buff_ptr += length;

    return new;
}

tlv_t * tlv_embed( tlv_t * parent, uint32_t type, uint32_t length, uint8_t instance, void *value)
{
	tlv_t * new = NULL, * root = NULL;
	new = tlv_get();

	new->type = type;
	new->length = length;
	new->instance = instance;
	new->value = value;

	root = tlv_find_root( parent);

	if(root->buff_allocated == 1) 
	{
		memcpy(root->buff_ptr, value, length);
		new->value = root->buff_ptr;
		root->buff_ptr += length;
	}

	if(parent->embedded == NULL) 
	{
		parent->embedded = new->head = new->tail = new;
		new->parent = parent;
	} 
	else 
	{
		new->head = parent->embedded;
		parent->embedded->tail->next = new;
		parent->embedded->tail = new;
	}

	return new;
}

uint32_t tlv_render( tlv_t * root, uint8_t * data, uint32_t length, uint8_t mode)
{
    tlv_t * curr = root;
    uint8_t * pos = data;
    uint8_t * blk = data;
    uint32_t embedded_len = 0;

    while(curr) 
	{
        pos = tlv_put_type( curr->type, pos, mode);
		
        if(curr->embedded == NULL) 
		{
            pos = tlv_put_length(curr->length, pos, mode);
            pos = tlv_put_instance(curr->instance, pos, mode);

            memcpy((char*)pos, (char*)curr->value, curr->length);
            pos += curr->length;
        } 
		else 
		{
            embedded_len = tlv_calc_length( curr->embedded, mode);
            pos = tlv_put_length( embedded_len, pos, mode);
            pos = tlv_put_instance( curr->instance, pos, mode);
            tlv_render( curr->embedded, pos, length - (uint32_t)(pos-blk), mode);
            
			pos += embedded_len;
        }
        curr = curr->next;
    }

    return (pos - blk);
}

tlv_t * tlv_parse_block( uint32_t length, void *data, uint8_t mode)
{
    uint8_t * pos = data;
    uint8_t * blk = data;

    tlv_t * root = NULL;
    tlv_t * prev = NULL;
    tlv_t * curr = NULL;

    root = curr = tlv_get();

    pos = tlv_get_element( curr, pos, mode);

    while(pos - blk < length) 
	{
        prev = curr;

        curr = tlv_get();
        prev->next = curr;

        pos = tlv_get_element( curr, pos, mode);
    }

    return root;
}

tlv_t * tlv_parse_embedded_block( tlv_t * tlv, uint8_t mode)
{
    tlv->embedded = tlv_parse_block( tlv->length, tlv->value, mode);
    return tlv->embedded;
}

tlv_t * tlv_find( tlv_t * root, uint32_t type)
{
    tlv_t * iter = root, *embed = NULL;
    
	while(iter) 
	{
        if(iter->type == type) 
		{
            return iter;
        }

        if(iter->embedded != NULL) 
		{
            embed = tlv_find( iter->embedded, type);
            if(embed != NULL) 
			{
                return embed;
            }
        }
        iter = iter->next;
    }

    return NULL;
}



tlv_t * tlv_add_leaf( tlv_t * parent_tlv, tlv_t * tlv, tlv_desc_t * desc, void * msg)
{
    switch (desc->ctype) 
	{
		case TLV_UINT8:
		case TLV_INT8:
		{
			tlv_uint8_t * v = ( tlv_uint8_t *)msg;
			if (parent_tlv)
				tlv = tlv_embed( parent_tlv, desc->type, 1, desc->instance, &v->u8);
			else
				tlv = tlv_add( tlv, desc->type, 1, desc->instance, &v->u8);
			break;
		}
		case TLV_UINT16:
		{
			tlv_uint16_t *v = (tlv_uint16_t *)msg;
			v->u16 = htobe16(v->u16);

			if (parent_tlv)
				tlv = tlv_embed( parent_tlv, desc->type, 2, desc->instance, &v->u16);
			else
				tlv = tlv_add( tlv, desc->type, 2, desc->instance, &v->u16);
			
			break;
		}
		case TLV_UINT24:
		case TLV_INT24:
		{
			tlv_uint24_t *v = (tlv_uint24_t *)msg;

			v->u24 = v->u24 << 8;
			v->u24 = htobe32(v->u24);

			if (parent_tlv)
				tlv = tlv_embed( parent_tlv, desc->type, 3, desc->instance, &v->u24);
			else
				tlv = tlv_add( tlv, desc->type, 3, desc->instance, &v->u24);
			break;
		}
		case TLV_UINT32:
		case TLV_INT32:
		{
			tlv_uint32_t *v = (tlv_uint32_t *)msg;

			v->u32 = htobe32(v->u32);

			if (parent_tlv)
				tlv = tlv_embed( parent_tlv, desc->type, 4, desc->instance, &v->u32);
			else
				tlv = tlv_add( tlv, desc->type, 4, desc->instance, &v->u32);
			break;
		}
		case TLV_FIXED_STR:
		{
			tlv_octet_t *v = (tlv_octet_t *)msg;

			if (parent_tlv)
				tlv = tlv_embed( parent_tlv, desc->type, desc->length, desc->instance, v->data);
			else
				tlv = tlv_add( tlv, desc->type, desc->length, desc->instance, v->data);
			break;
		}
		case TLV_VAR_STR:
		{
			tlv_octet_t *v = (tlv_octet_t *)msg;

			if (v->len == 0) 
			{
				printf("No TLV length - [%s] T:%d I:%d (vsz=%d)\n", desc->name, desc->type, desc->instance, desc->vsize);
			}

			if (parent_tlv) {
				tlv = tlv_embed( parent_tlv, desc->type, v->len, desc->instance, v->data);
			} else {
				tlv = tlv_add( tlv, desc->type, v->len, desc->instance, v->data);
			}	
			break;
		}
		case TLV_NULL:
		{
			if (parent_tlv)
				tlv = tlv_embed(parent_tlv, desc->type, 0, desc->instance, NULL);
			else
				tlv = tlv_add( tlv, desc->type, 0, desc->instance, NULL);
			break;
		}
		default:
			break;
    }

    return tlv;
}

uint32_t tlv_add_compound( tlv_t ** root, tlv_t * parent_tlv, tlv_desc_t * parent_desc, void * msg, int depth)
{
    tlv_presence_t * presence_p;
    tlv_desc_t * desc = NULL, * next_desc = NULL;
    tlv_t * tlv = NULL, * emb_tlv = NULL;
    uint8_t * p = msg;
    uint32_t offset = 0, count = 0;
    int i, j, r;
    char indent[17] = "                ";
	
	indent[ depth * 2] = 0;
    *root = NULL;
	
	for (i = 0, desc = parent_desc->child_descs[i]; desc != NULL; i++, desc = parent_desc->child_descs[i]) 
	{
        next_desc = parent_desc->child_descs[i+1];		
		
		if ( next_desc != NULL && next_desc->ctype == TLV_MORE) 
		{
			int offset2 = offset;
            for (j = 0; j < next_desc->length; j++) 
			{
                presence_p = (tlv_presence_t *)(p + offset2);

                if (*presence_p == 0)
                    break;

                if (desc->ctype == TLV_COMPOUND) 
				{
					if (parent_tlv) 
					{
                        tlv = tlv_embed( parent_tlv, desc->type, 0, desc->instance, NULL);
                    } 
					else 
					{
                        tlv = tlv_add( tlv, desc->type, 0, desc->instance, NULL);
					}
					
                    r = tlv_add_compound( &emb_tlv, tlv, desc, p + offset2 + sizeof(tlv_presence_t), depth + 1);
                    count += 1 + r;
                } 
				else 
				{
                    tlv = tlv_add_leaf( parent_tlv, tlv, desc, p + offset2);
                    count++;
                }

                if (*root == NULL)
                    *root = tlv;

                offset2 += desc->vsize;
            }
            offset += desc->vsize * next_desc->length;
            i++;
		}
		else
		{
			presence_p = (tlv_presence_t *)(p + offset);
			
			if (*presence_p) 
			{
				if ( desc->ctype == TLV_COMPOUND) 
				{
					if (parent_tlv) {
						tlv = tlv_embed( parent_tlv, desc->type, 0, desc->instance, NULL);
                    } else {
						tlv = tlv_add( tlv, desc->type, 0, desc->instance, NULL);
					}
					r = tlv_add_compound( &emb_tlv, tlv, desc, p + offset + sizeof(tlv_presence_t), depth + 1);
                    count += 1 + r;
				}
				else
				{
					tlv = tlv_add_leaf( parent_tlv, tlv, desc, p + offset);
                    count++;
				}
				
                if (*root == NULL)
                    *root = tlv;				
			}
			offset += desc->vsize;
		}
	}
	
	return count;
}

uint8_t * __si_buff__get_datapointer( __si_buff_t * buff);


__si_buff_t * pfcp_tlv_build_msg( tlv_desc_t * desc, void * msg, int mode)
{
	tlv_t * root = NULL;
	uint32_t r, length = 0, rendlen = 0;
	__si_buff_t * sbuf = NULL;

    if(desc->child_descs[0]) 
	{
        r = tlv_add_compound( &root, NULL, desc, msg, 0);
        length = tlv_calc_length(root, mode);
    }
	else 
	{
        length = 0;
    }
	

	sbuf = __si_buff__alloc( TLV_MAX_HEADROOM + length);
	__si_buff__reserve( sbuf, TLV_MAX_HEADROOM);			//16
	
	uint8_t * dataPtr = __si_buff__get_datapointer( sbuf);
	
    if(desc->child_descs[0]) 
	{
        rendlen = tlv_render( root, dataPtr, length, mode);
        tlv_free_all( root);
    }
	
	
	sbuf->len = rendlen;
	return sbuf;
}

tlv_desc_t * tlv_find_desc( uint8_t * desc_index, uint32_t * tlv_offset, tlv_desc_t * parent_desc, tlv_t * tlv)
{
    tlv_desc_t * prev_desc = NULL, *desc = NULL;
    int i, offset = 0;

    for (i = 0, desc = parent_desc->child_descs[i]; desc != NULL; i++, desc = parent_desc->child_descs[i]) 
	{
        if ( desc->type == tlv->type && desc->instance == tlv->instance) 
		{
            *desc_index = i;
            *tlv_offset = offset;
            break;
        }

        if ( desc->ctype == TLV_MORE) 
		{
            offset += prev_desc->vsize * (desc->length - 1);
        } 
		else 
		{
            offset += desc->vsize;
        }

        prev_desc = desc;
    }

    return desc;
}



int tlv_parse_leaf( void * msg, tlv_desc_t * desc, tlv_t * tlv)
{
	switch ( desc->ctype) 
	{
		case TLV_UINT8:
		case TLV_INT8:
		{
			tlv_uint8_t *v = (tlv_uint8_t *)msg;

			if (tlv->length != 1)
			{
				printf("Invalid TLV length %d. It should be 1\n", tlv->length);
				return -1;
			}
			v->u8 = *(uint8_t*)(tlv->value);
			break;
		}
		case TLV_UINT16:
		case TLV_INT16:
		{
			tlv_uint16_t *v = (tlv_uint16_t *)msg;

			if (tlv->length != 2)
			{
				printf("Invalid TLV length %d. It should be 2\n", tlv->length);
				return -1;
			}
			v->u16 = ((((uint8_t*)tlv->value)[0]<< 8)&0xff00) | ((((uint8_t*)tlv->value)[1]    )&0x00ff);
			break;
		}
		case TLV_UINT24:
		case TLV_INT24:
		{
			tlv_uint24_t *v = (tlv_uint24_t *)msg;

			if (tlv->length != 3)
			{
				printf("Invalid TLV length %d. It should be 3\n", tlv->length);
				return -1;
			}
			v->u24 = ((((uint8_t*)tlv->value)[0]<<16)&0x00ff0000) | ((((uint8_t*)tlv->value)[1]<< 8)&0x0000ff00) | ((((uint8_t*)tlv->value)[2]    )&0x000000ff);
			break;
		}
		case TLV_UINT32:
		case TLV_INT32:
		{
			tlv_uint32_t *v = (tlv_uint32_t *)msg;

			if (tlv->length != 4)
			{
				printf("Invalid TLV length %d. It should be 4\n", tlv->length);
				return -1;
			}
			v->u32 = ((((uint8_t*)tlv->value)[0]<<24)&0xff000000) |
				((((uint8_t*)tlv->value)[1]<<16)&0x00ff0000) |
				((((uint8_t*)tlv->value)[2]<< 8)&0x0000ff00) |
				((((uint8_t*)tlv->value)[3]    )&0x000000ff);
			break;
		}
		case TLV_FIXED_STR:
		{
			tlv_octet_t *v = (tlv_octet_t *)msg;

			if (tlv->length != desc->length)
			{
				printf("Invalid TLV length %d. It should be %d\n", tlv->length, desc->length);
				return -1;
			}

			v->data = tlv->value;
			v->len = tlv->length;
			break;
		}
		case TLV_VAR_STR:
		{
			tlv_octet_t *v = (tlv_octet_t *)msg;

			v->data = tlv->value;
			v->len = tlv->length;
			break;
		}
		case TLV_NULL:
		{
			if (tlv->length != 0) 
			{
				printf("Invalid TLV length %d. It should be 0\n", tlv->length);
				return -1;
			}
			break;
		}
		default:
			break;
	}

	return 1;
}

int tlv_parse_compound( void * msg, tlv_desc_t * parent_desc, tlv_t * parent_tlv, int depth, int mode)
{
	int rv;
	tlv_presence_t * presence_p = (tlv_presence_t *)msg;
	tlv_desc_t * desc = NULL, * next_desc = NULL;
	tlv_t * tlv = NULL, * emb_tlv = NULL;
	uint8_t * p = msg;
	uint32_t offset = 0;
	uint8_t index = 0;
	int i = 0, j;
	char indent[17] = "                ";
	
    indent[ depth * 2] = 0;

    tlv = parent_tlv;

   while (tlv) 
   {
        desc = tlv_find_desc( &index, &offset, parent_desc, tlv);
        if (desc == NULL) 
		{
            printf("Unexpected TLV type:%d\n", tlv->type);
            return -1;
        }
		
		presence_p = (tlv_presence_t *)(p + offset);
		next_desc = parent_desc->child_descs[index+1];

		if (next_desc != NULL && next_desc->ctype == TLV_MORE) 
		{
			for (j = 0; j < next_desc->length; j++) 
			{
				presence_p = (tlv_presence_t *)(p + offset + desc->vsize * j);
				if (*presence_p == 0) 
				{
					offset += desc->vsize * j;
					break;
				}
			}
			
			if (j == next_desc->length) 
			{
				printf("Multiple of the same type TLV need more room\n");
				tlv = tlv->next;
				continue;
			}
		}
		
		if (desc->ctype == TLV_COMPOUND) 
		{
            emb_tlv = tlv_parse_embedded_block( tlv, mode);
            if (emb_tlv == NULL) 
			{
                printf("Error while parse TLV\n");
                return -1;
            }

            offset += sizeof( tlv_presence_t);

            rv = tlv_parse_compound( p + offset, desc, emb_tlv, depth + 1, mode);
            if (rv != 1) 
			{
                printf("Can't parse compound TLV\n");
                return -1;
            }

            *presence_p = 1;
        } 
		else 
		{
			
            rv = tlv_parse_leaf(p + offset, desc, tlv);
            if (rv != 1) 
			{
                return -1;
            }
            *presence_p = 1;
        }
        tlv = tlv->next;
	}
	return 1;
}

int tlv_parse_msg( void * msg, tlv_desc_t * desc, __si_buff_t * pmsg, int mode)
{
    int rv = 1;
    tlv_t * root;
	tlv_t * temp_root;
	
    temp_root = root = tlv_parse_block( pmsg->len, pmsg->data, mode);
    if (root == NULL) 
	{
        return -1;
    }
	
	int total_tlv = 0;
	while( temp_root) 
	{
		total_tlv++;
		temp_root = temp_root->next;
	}
	
    
	if( pmsg->len > 0) {
		rv = tlv_parse_compound( msg, desc, root, 0, mode);
	}
	
	tlv_free_all(root);
	
    return rv;
}

__si_buff_t * pfcp_build__pfcp_association_setup_request( pfcp_association_setup_request_t * pfcp_association_setup_request)
{
	return pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_association_setup_request, pfcp_association_setup_request, TLV_MODE_T2_L2);
}

__si_buff_t * pfcp_build_msg( pfcp_message_t * pfcp_message)
{
	__si_buff_t * pmsg = NULL;
	
    switch( pfcp_message->h.type)
    {
        case PFCP_HEARTBEAT_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_heartbeat_request, &pfcp_message->pfcp_heartbeat_request, TLV_MODE_T2_L2);
            break;
        case PFCP_HEARTBEAT_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_heartbeat_response, &pfcp_message->pfcp_heartbeat_response, TLV_MODE_T2_L2);
            break;
        case PFCP_PFD_MANAGEMENT_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_pfd_management_request, &pfcp_message->pfcp_pfd_management_request, TLV_MODE_T2_L2);
            break;
        case PFCP_PFD_MANAGEMENT_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_pfd_management_response, &pfcp_message->pfcp_pfd_management_response, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_association_setup_request, &pfcp_message->pfcp_association_setup_request, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_association_setup_response, &pfcp_message->pfcp_association_setup_response, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_UPDATE_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_association_update_request, &pfcp_message->pfcp_association_update_request, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_UPDATE_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_association_update_response, &pfcp_message->pfcp_association_update_response, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_association_release_request, &pfcp_message->pfcp_association_release_request, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_RELEASE_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_association_release_response, &pfcp_message->pfcp_association_release_response, TLV_MODE_T2_L2);
            break;
        case PFCP_VERSION_NOT_SUPPORTED_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_version_not_supported_response, &pfcp_message->pfcp_version_not_supported_response, TLV_MODE_T2_L2);
            break;
        case PFCP_NODE_REPORT_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_node_report_request, &pfcp_message->pfcp_node_report_request, TLV_MODE_T2_L2);
            break;
        case PFCP_NODE_REPORT_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_node_report_response, &pfcp_message->pfcp_node_report_response, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_SET_DELETION_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_set_deletion_request, &pfcp_message->pfcp_session_set_deletion_request, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_SET_DELETION_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_set_deletion_response, &pfcp_message->pfcp_session_set_deletion_response, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_establishment_request, &pfcp_message->pfcp_session_establishment_request, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_establishment_response, &pfcp_message->pfcp_session_establishment_response, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_modification_request, &pfcp_message->pfcp_session_modification_request, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_MODIFICATION_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_modification_response, &pfcp_message->pfcp_session_modification_response, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_DELETION_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_deletion_request, &pfcp_message->pfcp_session_deletion_request, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_DELETION_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_deletion_response, &pfcp_message->pfcp_session_deletion_response, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_REPORT_REQUEST_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_report_request, &pfcp_message->pfcp_session_report_request, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_REPORT_RESPONSE_TYPE:
            pmsg = pfcp_tlv_build_msg( &pfcp_msg_desc_pfcp_session_report_response, &pfcp_message->pfcp_session_report_response, TLV_MODE_T2_L2);
            break;
        default:
            printf("Not implmeneted(type:%d)\n", pfcp_message->h.type);
            break;
    }

    return pmsg;
}


int pfcp_parse_msg( pfcp_message_t * pfcp_message, __si_buff_t * pmsg)
{
    int rv = 0;
	
	switch( pfcp_message->h.type)
    {
        case PFCP_HEARTBEAT_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_heartbeat_request, 0, sizeof(pfcp_heartbeat_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_heartbeat_request, &pfcp_msg_desc_pfcp_heartbeat_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_HEARTBEAT_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_heartbeat_response, 0, sizeof(pfcp_heartbeat_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_heartbeat_response, &pfcp_msg_desc_pfcp_heartbeat_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_PFD_MANAGEMENT_REQUEST_TYPE:
			memset( &pfcp_message->pfcp_pfd_management_request, 0, sizeof(pfcp_pfd_management_request_t));
            rv = tlv_parse_msg( &pfcp_message->pfcp_pfd_management_request, &pfcp_msg_desc_pfcp_pfd_management_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_PFD_MANAGEMENT_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_pfd_management_response, 0, sizeof(pfcp_pfd_management_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_pfd_management_response, &pfcp_msg_desc_pfcp_pfd_management_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_association_setup_request, 0, sizeof(pfcp_association_setup_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_association_setup_request, &pfcp_msg_desc_pfcp_association_setup_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_association_setup_response, 0, sizeof(pfcp_association_setup_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_association_setup_response, &pfcp_msg_desc_pfcp_association_setup_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_UPDATE_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_association_update_request, 0, sizeof(pfcp_association_update_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_association_update_request, &pfcp_msg_desc_pfcp_association_update_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_UPDATE_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_association_update_response, 0, sizeof(pfcp_association_update_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_association_update_response, &pfcp_msg_desc_pfcp_association_update_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_association_release_request, 0, sizeof(pfcp_association_release_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_association_release_request, &pfcp_msg_desc_pfcp_association_release_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_ASSOCIATION_RELEASE_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_association_release_response, 0, sizeof(pfcp_association_release_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_association_release_response, &pfcp_msg_desc_pfcp_association_release_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_VERSION_NOT_SUPPORTED_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_version_not_supported_response, 0, sizeof(pfcp_version_not_supported_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_version_not_supported_response, &pfcp_msg_desc_pfcp_version_not_supported_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_NODE_REPORT_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_node_report_request, 0, sizeof(pfcp_node_report_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_node_report_request, &pfcp_msg_desc_pfcp_node_report_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_NODE_REPORT_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_node_report_response, 0, sizeof(pfcp_node_report_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_node_report_response, &pfcp_msg_desc_pfcp_node_report_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_SET_DELETION_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_session_set_deletion_request, 0, sizeof(pfcp_session_set_deletion_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_set_deletion_request, &pfcp_msg_desc_pfcp_session_set_deletion_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_SET_DELETION_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_session_set_deletion_response, 0, sizeof(pfcp_session_set_deletion_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_set_deletion_response, &pfcp_msg_desc_pfcp_session_set_deletion_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
			memset( &pfcp_message->pfcp_session_establishment_request, 0, sizeof(pfcp_session_establishment_request_t));
            rv = tlv_parse_msg( &pfcp_message->pfcp_session_establishment_request, &pfcp_msg_desc_pfcp_session_establishment_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_session_establishment_response, 0, sizeof(pfcp_session_establishment_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_establishment_response, &pfcp_msg_desc_pfcp_session_establishment_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_session_modification_request, 0, sizeof(pfcp_session_modification_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_modification_request, &pfcp_msg_desc_pfcp_session_modification_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_MODIFICATION_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_session_modification_response, 0, sizeof(pfcp_session_modification_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_modification_response, &pfcp_msg_desc_pfcp_session_modification_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_DELETION_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_session_deletion_request, 0, sizeof(pfcp_session_deletion_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_deletion_request, &pfcp_msg_desc_pfcp_session_deletion_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_DELETION_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_session_deletion_response, 0, sizeof(pfcp_session_deletion_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_deletion_response, &pfcp_msg_desc_pfcp_session_deletion_response, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_REPORT_REQUEST_TYPE:
            memset( &pfcp_message->pfcp_session_report_request, 0, sizeof(pfcp_session_report_request_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_report_request, &pfcp_msg_desc_pfcp_session_report_request, pmsg, TLV_MODE_T2_L2);
            break;
        case PFCP_SESSION_REPORT_RESPONSE_TYPE:
            memset( &pfcp_message->pfcp_session_report_response, 0, sizeof(pfcp_session_report_response_t));
			rv = tlv_parse_msg( &pfcp_message->pfcp_session_report_response, &pfcp_msg_desc_pfcp_session_report_response, pmsg, TLV_MODE_T2_L2);
            break;
        default:
            printf("Not implmeneted(type:%d)\n", pfcp_message->h.type);
            break;
    }	
	
	return rv;
}


		

void pfcp__set_request_header( __si_buff_t * pmsg, uint8_t type, uint32_t seqNo, uint8_t seid_presence, uint64_t seid)
{
	pfcp_sh_t * sh = (pfcp_sh_t *)__si_buff__get_datapointer( pmsg);
	
	sh->version = 1;
	sh->spare1 = 0;
	sh->mp = 0;
	sh->seid_presence = seid_presence;

	uint16_t len = (pmsg->len-4);

	uint8_t* data = (uint8_t*) __si_buff__get_datapointer( pmsg);

	data[1] = type;
	data[2] = (len >> 8) & 0xFF;
	data[3] = (len) & 0xFF;
	
	if( seid_presence == 1)
	{
		data[4] = (seid >> 56) & 0xFF;
		data[5] = (seid >> 48) & 0xFF;
		data[6] = (seid >> 40) & 0xFF;
		data[7] = (seid >> 32) & 0xFF;
		data[8] = (seid >> 24) & 0xFF;
		data[9] = (seid >> 16) & 0xFF;
		data[10] = (seid >> 8) & 0xFF;
		data[11] = seid & 0xFF;
		
		data[12] = (seqNo >> 16) & 0xFF;
		data[13] = (seqNo >> 8) & 0xFF;
		data[14] = (seqNo) & 0xFF;
		data[15] = 0;
	}
	else
	{
		data[4] = (seqNo >> 16) & 0xFF;
		data[5] = (seqNo >> 8) & 0xFF;
		data[6] = (seqNo) & 0xFF;
		data[7] = 0;
	}
	
}














































__si_pfcp_t * __pfcpStack = NULL;


void __si_pfcp__send_heartBeatRequest( __si_pfcp_node_t * node)
{
	pfcp_message_t pfcp_message;
    pfcp_heartbeat_request_t * req = NULL;
	
	req = &pfcp_message.pfcp_heartbeat_request;
    memset(&pfcp_message, 0, sizeof(pfcp_message_t));

    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = __si_core__get_start_time_as_u32(0);

    pfcp_message.h.type = PFCP_HEARTBEAT_REQUEST_TYPE;
    __si_buff_t * pmsg = pfcp_build_msg( &pfcp_message);
	
	__si_buff__pull( pmsg, 8, 1);
	pfcp__set_request_header( pmsg, PFCP_HEARTBEAT_REQUEST_TYPE, __si_pfcp__get_seqno(), 0, 0);
	
	int sentBytes = __si_socket_engine_udp_send_response( __pfcpStack->serverSocket->fd, (struct sockaddr *) &node->addr, sizeof(struct sockaddr_in), pmsg->data, pmsg->len);
	
	if( sentBytes <= 0) 
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "sending heart-beat message failed ip=%s port=%d sentBytes=%d errno=%d  %s|%s|%d", node->address, node->port, sentBytes, errno, __FILE__, __FUNCTION__, __LINE__);
	}
}





void __si_pfcp__sendAssociationSetupRequest( __si_pfcp_node_t * node)
{
	node->isAssociationStarted = 0;
	
	pfcp_association_setup_request_t * req = (pfcp_association_setup_request_t *) __si_allocM(sizeof(pfcp_association_setup_request_t));
	memset( req, 0, sizeof(pfcp_association_setup_request_t));
	
	char node_id[20];
    int node_id_len = 0;

	if( node->ipversion == 4)
	{
		node_id[0] = 0;
		node_id_len = 5;
		
		node_id[1] = (__pfcpStack->addr.sin_addr.s_addr) & 0xFF;
		node_id[2] = (__pfcpStack->addr.sin_addr.s_addr >> 8) & 0xFF;
		node_id[3] = (__pfcpStack->addr.sin_addr.s_addr >> 16) & 0xFF;
		node_id[4] = (__pfcpStack->addr.sin_addr.s_addr >> 24) & 0xFF;		
	}
	
	req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = node_id_len;
	
	req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = __si_core__get_start_time_as_u32(0);

    req->cp_function_features.presence = 1;
    req->cp_function_features.u8 = 0x11;

	__si_buff_t * pmsg = pfcp_build__pfcp_association_setup_request( req);
	
	__si_buff__pull( pmsg, 8, 1);
	pfcp__set_request_header( pmsg, PFCP_ASSOCIATION_SETUP_REQUEST_TYPE, __si_pfcp__get_seqno(), 0, 0);
	
	int sentBytes = __si_socket_engine_udp_send_response( __pfcpStack->serverSocket->fd, (struct sockaddr *) &node->addr, sizeof(struct sockaddr_in), __si_buff__get_datapointer( pmsg), pmsg->len);
	
	if( sentBytes == pmsg->len) {
		node->isAssociationStarted = 1;
	} else {
		node->isAssociationStarted = 2;
	}
	
	__si_log( SI_STK_LOG, 0, SI_LOG_CRITICAL, "sending PFCP association request to %08X|%s sentBytes=%d errno=%d  %s|%s|%d", 
		node->addr.sin_addr.s_addr, __si_core_convert_inttoipv4(node->addr.sin_addr.s_addr), sentBytes, errno, __FILE__, __FUNCTION__, __LINE__);
	
	gettimeofday( &node->lastmsgsent, NULL);
	__si_freeMV( req);
	__si_buff__free( pmsg);
}




void __si_pfcp__checkAssociations()
{
	__si_pfcp_node_t * node = __pfcpStack->nodeHead;
	
	struct timeval after;
	gettimeofday( &after, NULL);
	
	while( node)
	{
		if( __pfcpStack->type == PFCP_NODE_TYPE__GATWEAY)
		{
			if( node->isAssociationStarted == 0)
			{
				__si_pfcp__sendAssociationSetupRequest( node);
			}
			else if( node->isAssociationStarted == 1 || node->isAssociationStarted == 2)
			{
				uint64_t tv_sec  = after.tv_sec - node->lastmsgsent.tv_sec;

				if( tv_sec > 6)
				{
					__si_pfcp__sendAssociationSetupRequest( node);
				}
			}
		}
		
		if( node->isAssociationStarted == 4)
		{
			if( node->pending_heartbeat_response < 4)
			{
				uint64_t tv_sec  = after.tv_sec - node->lastheartbeatsent.tv_sec;
				
				if( (tv_sec > 10 && node->nodeType == PFCP_NODE_TYPE__GATWEAY) || (tv_sec > 12 && node->nodeType == PFCP_NODE_TYPE__USERPLANE))  
				{
					__si_pfcp__send_heartBeatRequest( node);
					gettimeofday( &node->lastheartbeatsent, NULL);
					node->pending_heartbeat_response++;
				}
			}
			else
			{
				node->pending_heartbeat_response = 0;
				node->isAssociationStarted = 0;
			}
		}
		
		node = node->Next;
	}
}


void * __si_pfcp__event_thread( void * args)
{
	__si_log( SI_STK_LOG, 0, SI_LOG_CRITICAL, "Started PFCP Event Thread   %s|%s|%d", __FILE__, __FUNCTION__, __LINE__);
	
	while(1)
	{
		 __si_pfcp__checkAssociations();
		usleep(999999);
	}
}


				
__si_pfcp_node_t * __si_pfcp__find_node_by_ip( u_char * ip, int ipv, int port, int add)
{
	__si_pfcp_node_t * node = __pfcpStack->nodeHead;
	
	while( node)
	{
		if( ipv == 4)
		{
			if( strcmp( node->address, ip) == 0 && node->port == port)
			{
				return node;
			}
		}
		node = node->Next;
	}
	
	if( add == 1)
	{	
		pthread_mutex_lock( &__pfcpStack->nodeLock);
		
		node = (__si_pfcp_node_t *) malloc(sizeof(__si_pfcp_node_t));
		memset( node, 0, sizeof(__si_pfcp_node_t));
		
		node->sessionTable 	= __si_power_table_create();
		node->teidTable 	= __si_power_table_create();
		node->port = port;
		node->ipversion = ipv;
		strcpy( node->address, ip);
		
		if( ipv == 4) 
		{
			node->addr.sin_family = AF_INET;
			node->addr.sin_port = htons( port);
			node->addr.sin_addr.s_addr = inet_addr( ip);
		}
	
		if(!__pfcpStack->nodeHead)
		{
			__pfcpStack->nodeHead = __pfcpStack->nodeCurrent = node;
		}
		else
		{
			__pfcpStack->nodeCurrent->Next = node;
			__pfcpStack->nodeCurrent = node;
		}

		gettimeofday( &node->lastheartbeatsent, NULL);
		gettimeofday( &node->lastmsgsent, NULL);
		node->pending_heartbeat_response = 0;
		
		node->isAssociationStarted = 0;
		node->id = __pfcpStack->nodeCount;
		__pfcpStack->nodeCount++;
	
		pthread_mutex_unlock( &__pfcpStack->nodeLock);
		return node;
	}
	
	return NULL;
}


void __si_pfcp__handle_association_setup_response( pfcp_message_t * pfcp_response, __si_pfcp_node_t * pNode, uint32_t seqNo)
{
	gettimeofday( &pNode->lastmsg, NULL);

    pfcp_association_setup_response_t * res = &pfcp_response->pfcp_association_setup_response;
	pNode->isAssociationStarted = 4;
}


void __si_pfcp__handle_heartbeat_request( pfcp_message_t * pfcp_request, __si_pfcp_node_t * pNode, uint32_t seqNo)
{
	gettimeofday( &pNode->lastmsg, NULL);
	
	pfcp_heartbeat_request_t * req = &pfcp_request->pfcp_heartbeat_request;
	
	pfcp_message_t pfcp_response;
    pfcp_heartbeat_response_t * res = &pfcp_response.pfcp_heartbeat_response;
	
    memset(&pfcp_response, 0, sizeof(pfcp_message_t));

    res->recovery_time_stamp.presence = 1;
    res->recovery_time_stamp.u32 = __si_core__get_start_time_as_u32(0);

    pfcp_response.h.type = PFCP_HEARTBEAT_RESPONSE_TYPE;
    __si_buff_t * pmsg = pfcp_build_msg( &pfcp_response);
	
	__si_buff__pull( pmsg, 8, 1);
	pfcp__set_request_header( pmsg, PFCP_HEARTBEAT_RESPONSE_TYPE, seqNo, 0, 0);
	
	int sentBytes = __si_socket_engine_udp_send_response( __pfcpStack->serverSocket->fd, (struct sockaddr *) &pNode->addr, sizeof(struct sockaddr_in), pmsg->data, pmsg->len);
	
	if( sentBytes <= 0) {
		__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "sending heartbeat response failed to ip=%s port=%d  %s|%s|%d", pNode->address, pNode->port, __FILE__, __FUNCTION__, __LINE__);
	}
	
	__si_buff__free( pmsg);
}



void __si_pfcp__handle_association_setup_request( pfcp_message_t * pfcp_message, __si_pfcp_node_t * pNode, uint32_t seqNo)
{
	__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "received pfcp association request from ip=%s port=%d  %s|%s|%d", pNode->address, pNode->port, __FILE__, __FUNCTION__, __LINE__);
	
	gettimeofday( &pNode->lastmsg, NULL);
	
    pfcp_association_setup_request_t * req = &pfcp_message->pfcp_association_setup_request;

    pfcp_message_t pfcp_response;
    pfcp_association_setup_response_t * res = &pfcp_response.pfcp_association_setup_response;
    memset(&pfcp_response, 0, sizeof(pfcp_message_t));

	res->cause.presence = 1;
    res->cause.u8 = PFCP_CAUSE_REQUEST_ACCEPTED;
	
	char node_id[20];
    int node_id_len = 0;


	if( __pfcpStack->ipversion == 4)
	{
		node_id[0] = 0;
		node_id_len = 5;
		
		node_id[1] = (__pfcpStack->addr.sin_addr.s_addr) & 0xFF;
		node_id[2] = (__pfcpStack->addr.sin_addr.s_addr >> 8) & 0xFF;
		node_id[3] = (__pfcpStack->addr.sin_addr.s_addr >> 16) & 0xFF;
		node_id[4] = (__pfcpStack->addr.sin_addr.s_addr >> 24) & 0xFF;
	}

	res->node_id.presence = 1;
    res->node_id.data = &node_id;
    res->node_id.len = node_id_len;
	
	res->recovery_time_stamp.presence = 1;
    res->recovery_time_stamp.u32 = __si_core__get_start_time_as_u32(0);;

	unsigned char uc_upinfo[50];
	memset( uc_upinfo, 0, sizeof(uc_upinfo));

	uc_upinfo[0] |= 1 << 0;	
	uc_upinfo[0] |= 1 << 5;	
	uc_upinfo[1] = (__pfcpStack->addr.sin_addr.s_addr) & 0xFF;
	uc_upinfo[2] = (__pfcpStack->addr.sin_addr.s_addr >> 8) & 0xFF;
	uc_upinfo[3] = (__pfcpStack->addr.sin_addr.s_addr >> 16) & 0xFF;
	uc_upinfo[4] = (__pfcpStack->addr.sin_addr.s_addr >> 24) & 0xFF;
		
	memcpy( &uc_upinfo[5], " internet", 9);

	pfcp_tlv_user_plane_ip_resource_information_t * upinfo = &res->user_plane_ip_resource_information[0];
	upinfo->presence = 1;
    upinfo->data = &uc_upinfo;
    upinfo->len = 14;
	

	unsigned char up_function_features_data[2] = { 0x0, 0x0};

    res->up_function_features.presence = 1;
    res->up_function_features.data = &up_function_features_data;
	res->up_function_features.len = 2;

    pfcp_response.h.type = PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE;
    __si_buff_t * pmsg = pfcp_build_msg( &pfcp_response);
	
	__si_buff__pull( pmsg, 8, 1);
	pfcp__set_request_header( pmsg, PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE, seqNo, 0, 0);
	
	int sentBytes = __si_socket_engine_udp_send_response( __pfcpStack->serverSocket->fd, (struct sockaddr *) &pNode->addr, sizeof(struct sockaddr_in), pmsg->data, pmsg->len);
	
	if( sentBytes <= 0)
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "sending pfcp association response failed to ip=%s port=%d  %s|%s|%d", pNode->address, pNode->port, __FILE__, __FUNCTION__, __LINE__);
	}
	else
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "sending pfcp association response success to ip=%s port=%d  %s|%s|%d", pNode->address, pNode->port, __FILE__, __FUNCTION__, __LINE__);
		pNode->isAssociationStarted = 4;
	}
}


int __si_pfcp__send_msg( __si_pfcp_node_t * node, __si_buff_t * pmsg)
{
	int sentBytes = __si_socket_engine_udp_send_response( __pfcpStack->serverSocket->fd, (struct sockaddr *) &node->addr, sizeof(struct sockaddr_in), pmsg->data, pmsg->len);
	__si_buff__free( pmsg);
	return sentBytes;
}


fp_onpfcp_msg mgs_handler = NULL;
void __si_pfcp__setOnPfcpMsg( fp_onpfcp_msg fp)
{
	mgs_handler = fp;
}


void __si_pfcp__udp_server_receive_queue( SI_SocketUdpBuffer * udpBuffer, int i)
{
	char str[INET_ADDRSTRLEN];
	char sIpv6addr[17];
	int ipv = 4;
	int port = 0;
	
	if( udpBuffer->clientlen == sizeof(struct sockaddr_in))
	{
		inet_ntop( AF_INET, &udpBuffer->clientaddr.sin_addr, str, INET_ADDRSTRLEN);
		port = ntohs(udpBuffer->clientaddr.sin_port);
	}
	else
	{
		ipv = 6;
	}
	
	__si_pfcp_node_t * pNode = __si_pfcp__find_node_by_ip( str, ipv, port, 1);

	pfcp_sh_t * sh = (pfcp_sh_t *) udpBuffer->buff;
	
	if( sh->version != 1)
	{	
		__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "received unsupported pfcp version=%u  %s|%s|%d", sh->version, __FILE__, __FUNCTION__, __LINE__);
		__si_socket_engine_release_socket_udp_buffer( udpBuffer);
		return; 
	}
	
	uint8_t headerLen = 8;
	uint8_t hasSEID = sh->seid_presence;
	uint32_t seqNo = 0;
	uint64_t SEID = 0;
	uint8_t msgType = 8;
	
	if( hasSEID == 1) 
	{
		headerLen = 16;
	}
	
	msgType = udpBuffer->buff[1];
	uint16_t len = ((udpBuffer->buff[2] << 8) & 0xFF00) + ((udpBuffer->buff[3]) & 0x00FF);

	
	if( len != (udpBuffer->len-4))
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "received invalid pfcp length expected=%u received=%u (after -4)  %s|%s|%d", 
			len, (udpBuffer->len-4), __FILE__, __FUNCTION__, __LINE__);
		__si_socket_engine_release_socket_udp_buffer( udpBuffer);
		return;
	}
	
	if( hasSEID)
	{
		uint8_t bv1 = udpBuffer->buff[4];
		uint8_t bv2 = udpBuffer->buff[5];
		uint8_t bv3 = udpBuffer->buff[6];
		uint8_t bv4 = udpBuffer->buff[7];
		uint8_t bv5 = udpBuffer->buff[8];
		uint8_t bv6 = udpBuffer->buff[9];
		uint8_t bv7 = udpBuffer->buff[10];
		uint8_t bv8 = udpBuffer->buff[11];
		
		SEID = ((((uint64_t)bv1 << 56) & 0xFF00000000000000U) + (((uint64_t)bv2 << 48) & 0x00FF000000000000U) + (((uint64_t)bv3 << 40) & 0x0000FF0000000000U) + (((uint64_t)bv4 << 32) & 0x000000FF00000000U) + ((bv5 << 24) & 0x00000000FF000000U) + ((bv6 << 16) & 0x0000000000FF0000U) + ((bv7 << 8) & 0x000000000000FF00U) + (bv8 & 0x00000000000000FFU));
		seqNo = __si_get_u24( &udpBuffer->buff[12]);
	}
	else
	{
		seqNo = __si_get_u24( &udpBuffer->buff[4]);
	}
	

	if( msgType >= PFCP_HEARTBEAT_REQUEST_TYPE && msgType <= PFCP_SESSION_REPORT_RESPONSE_TYPE)
	{
		pfcp_message_t pfcp_message2;
		pfcp_message2.h.type = msgType;
		
		__si_buff_t * sbuf = NULL;
		
		if( hasSEID) {
			sbuf = __si_buff__alloc2( &udpBuffer->buff[16], udpBuffer->len-16);
		} else {
			sbuf = __si_buff__alloc2( &udpBuffer->buff[8], udpBuffer->len-8);
		}
		
		int rv = pfcp_parse_msg( &pfcp_message2, sbuf);
		
		if( rv == 1)
		{
			switch( msgType)
			{
				case PFCP_HEARTBEAT_REQUEST_TYPE:
					__si_pfcp__handle_heartbeat_request( &pfcp_message2, pNode, seqNo);
					break;
				case PFCP_HEARTBEAT_RESPONSE_TYPE:
					if( pNode->pending_heartbeat_response > 0)
					{	
						pNode->pending_heartbeat_response--;
					}
					break;
				case PFCP_PFD_MANAGEMENT_REQUEST_TYPE:
					break;
				case PFCP_PFD_MANAGEMENT_RESPONSE_TYPE:
					break;
				case PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
					__si_pfcp__handle_association_setup_request( &pfcp_message2, pNode, seqNo);
					break;
				case PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
					__si_pfcp__handle_association_setup_response( &pfcp_message2, pNode, seqNo);
					break;
				case PFCP_ASSOCIATION_UPDATE_REQUEST_TYPE:
					break;
				case PFCP_ASSOCIATION_UPDATE_RESPONSE_TYPE:
					break;
				case PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE:
					break;
				case PFCP_ASSOCIATION_RELEASE_RESPONSE_TYPE:
					break;
				case PFCP_VERSION_NOT_SUPPORTED_RESPONSE_TYPE:
					break;
				case PFCP_NODE_REPORT_REQUEST_TYPE:
					break;
				case PFCP_NODE_REPORT_RESPONSE_TYPE:
					break;
				case PFCP_SESSION_SET_DELETION_REQUEST_TYPE:
					break;
				case PFCP_SESSION_SET_DELETION_RESPONSE_TYPE:
					break;
				case PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
				case PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE:
				case PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
				case PFCP_SESSION_MODIFICATION_RESPONSE_TYPE:
				case PFCP_SESSION_DELETION_REQUEST_TYPE:
				case PFCP_SESSION_DELETION_RESPONSE_TYPE:
				case PFCP_SESSION_REPORT_REQUEST_TYPE:
				case PFCP_SESSION_REPORT_RESPONSE_TYPE: 
					{
						if( mgs_handler > 0) 
						{
							mgs_handler( &pfcp_message2, pNode, seqNo, SEID);
						}
					}
					break;
				default:
					break;
			}
		}
		else
		{
			__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "pfcp-message decodeding failed %s|%s|%d", __FILE__, __FUNCTION__, __LINE__);
		}
		
		__si_buff__free( sbuf);
		__si_socket_engine_release_socket_udp_buffer( udpBuffer);
	}
	else
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "received invalid msg-type=%u %s|%s|%d", msgType, __FILE__, __FUNCTION__, __LINE__);
		__si_socket_engine_release_socket_udp_buffer( udpBuffer);
		return;
	}
}


void __si_pfcp__udp_server_receive( SI_SocketUdpBuffer * udpBuffer)
{
	__si_core_queue_item_force( __pfcpStack->pfcpMsgQueue, udpBuffer, 1);
}

SI_Socket * __si_socket_engine_create_server_socket( char * ip, int ipversion, int transportType, int port, int tls, char * serverCert, char * pKey);

void __si_pfcp__start_server()
{
	__si_log( SI_STK_LOG, 0, SI_LOG_CRITICAL, "starting pfcp server at UDP IP=%s Port=%u %s|%s|%d", __pfcpStack->address, __pfcpStack->port, __FILE__, __FUNCTION__, __LINE__);
	__pfcpStack->serverSocket = __si_socket_engine_create_server_socket( __pfcpStack->address, __pfcpStack->ipversion, SIRIK_TRANSPORT_TYPE_UDP, __pfcpStack->port, 0, NULL, NULL);
	__pfcpStack->serverSocket->OnUdpPacketReceive = __si_pfcp__udp_server_receive;
	__si_socketEngine->Start( __pfcpStack->serverSocket);
}

void __si_pfcp__set_accessip( u_char * ipaddress, __si_pfcp_node_t * node)
{
	node->upfAccesIP = inet_addr( ipaddress);
}

uint32_t __si_pfcp__get_accessip( __si_pfcp_node_t * node)
{
	return node->upfAccesIP;
}

__si_pfcp_node_t * __si_pfcp__add_upf( u_char * ipaddress, int ipv, int port)
{
	__si_pfcp_node_t * node = (__si_pfcp_node_t *) malloc(sizeof(__si_pfcp_node_t));
	memset( node, 0, sizeof(__si_pfcp_node_t));
	
	node->sessionTable 	= __si_power_table_create();
	node->teidTable 	= __si_power_table_create();
	node->port = port;
	node->ipversion = ipv;
	strcpy( node->address, ipaddress);
	
	pthread_mutex_lock( &__pfcpStack->nodeLock);
	
	if(!__pfcpStack->nodeHead)
	{
		__pfcpStack->nodeHead = __pfcpStack->nodeCurrent = node;
	}
	else
	{
		__pfcpStack->nodeCurrent->Next = node;
		__pfcpStack->nodeCurrent = node;
	}
	
	node->nodeType = 2;
	node->id = __pfcpStack->nodeCount;
	
	__pfcpStack->nodeCount++;
	
	pthread_mutex_unlock( &__pfcpStack->nodeLock);
	
	node->isAssociationStarted = 0;
	gettimeofday( &node->lastheartbeatsent, NULL);
	gettimeofday( &node->lastmsgsent, NULL);
	node->pending_heartbeat_response = 0;
	
	if( ipv == 4) 
	{
		node->addr.sin_family = AF_INET;
		node->addr.sin_port = htons( port);
		node->addr.sin_addr.s_addr = inet_addr( ipaddress);
	}
	else
	{
		printf("IPv6 Not Implemented in PFCP  %s|%s|%d\n", __FILE__, __FUNCTION__, __LINE__);
		exit(0);
	}
	
	__si_log( SI_STK_LOG, 0, SI_LOG_CRITICAL, "PFCP-added UPF Node IP=%s Port=%u %s|%s|%d", ipaddress, port, __FILE__, __FUNCTION__, __LINE__);
	
	return node;
}


struct sockaddr_in * __si_pfcp__getIPv4_addr()
{
	return &__pfcpStack->addr;
}

struct sockaddr_in6 * __si_pfcp__getIPv6_addr()
{
	return &__pfcpStack->addr6;
}

__si_pfcp_node_t * __si_pfcp__get_root_node()
{
	return __pfcpStack->nodeHead;
}

__si_pfcp_node_t * __si_pfcp__get_next_node( __si_pfcp_node_t * node)
{
	if( node) return node->Next;
	return NULL;
}

void __si_pfcp__set_ipv4_addr( pfcp_node_id_t * node)
{
	
}

void __si_pfcp__pts( void * v, int i){}


uint32_t __si_pfcp__get_seqno()
{
	pthread_mutex_lock( &__pfcpStack->seqLock);
	uint32_t seqNo = __pfcpStack->seqNo++;
	pthread_mutex_unlock( &__pfcpStack->seqLock);
	
	return seqNo;
}

int __si_pfcp__node_ipversion()
{
	return __pfcpStack->ipversion;
}


void __si_pfcp__initalize( int type, int port, int ipver, char * address, int nodeIdType, char * nodeIdValue)
{
	if(!__pfcpStack)
	{
		__pfcpStack = (__si_pfcp_t *) malloc( sizeof(__si_pfcp_t));
		memset( __pfcpStack, 0, sizeof(__si_pfcp_t));
		
		__si_socket_engine_init();
		
		__pfcpStack->type = type;
		__pfcpStack->port = port;
		strcpy( __pfcpStack->address, address);
		__pfcpStack->ipversion = ipver;
		
		if( ipver == 4)
		{	
			__pfcpStack->addr.sin_addr.s_addr = inet_addr( __pfcpStack->address);
			__pfcpStack->addr.sin_port = htons( port);
		}
		
		__pfcpStack->nodeIdType = nodeIdType;
		strcpy( __pfcpStack->nodeIdValue, nodeIdValue);

		__pfcpStack->nodeHead = NULL;
		__pfcpStack->nodeCurrent = NULL;
		__pfcpStack->nodeCount = 0;
		pthread_mutex_init( &__pfcpStack->nodeLock, NULL);
		
		if( type == 1) {
			__pfcpStack->seqNo = __si_core_getU32RANDRange( 100, 200);
		} else {
			__pfcpStack->seqNo = __si_core_getU32RANDRange( 200, 300);
		}
		
		pthread_mutex_init( &__pfcpStack->seqLock, NULL);
		
		__si_pfcp__start_server();
		
		__si_core_create_queue( (void **) &__pfcpStack->pfcpMsgQueue, (void (*)(void*, int))__si_pfcp__udp_server_receive_queue, 1, 5000);

		__si_create_pthread2( __si_pfcp__event_thread, NULL, "pfcp-evt");
		
		__si_log( SI_STK_LOG, 0, SI_LOG_CRITICAL, "PFCP Stack Initalized wit host address=%s port=%d ip-ver=%d   %s|%s|%d", address, port, ipver, __FILE__, __FUNCTION__, __LINE__);
	}
}













