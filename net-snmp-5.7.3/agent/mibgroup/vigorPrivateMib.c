/*
 * Note: this file originally edit by lei.deng
 * 
 */
 
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/vigor_type.h>
#include "vigorPrivateMib.h"


void
init_vigorPubMIBObject(void)
{
    static oid      vigorIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 3, 1, 1, 0 };
    static oid      vigorSubnetMask_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 3, 1, 2, 0 };
    static oid      vigorGateway_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 3, 1, 3, 0 };
    static oid      vigorDBIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 3, 1, 4, 0 };
    static oid      vigorEquipmentType_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 3, 1, 5, 0 };
    static oid      vigorSource_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 3, 1, 6, 0 };
    static oid      vigorDeviceState_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 3, 1, 7, 0 };

    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("vigorIpAddress",
                               do_vigorIpAddress,
                               vigorIpAddress_oid,
                               OID_LENGTH(vigorIpAddress_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("vigorSubnetMask",
                               do_vigorSubnetMask,
                               vigorSubnetMask_oid,
                               OID_LENGTH(vigorSubnetMask_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("vigorGateway",
                               do_vigorGateway,
                               vigorGateway_oid,
                               OID_LENGTH(vigorGateway_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("vigorDBIpAddress",
                               do_vigorDBIpAddress,
                               vigorDBIpAddress_oid,
                               OID_LENGTH(vigorDBIpAddress_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("vigorEquipmentType",
                                         get_vigorEquipmentType,
                                         vigorEquipmentType_oid,
                                         OID_LENGTH
                                         (vigorEquipmentType_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("vigorSource", get_vigorSource,
                                         vigorSource_oid,
                                         OID_LENGTH(vigorSource_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("vigorDeviceState",
                                         get_vigorDeviceState,
                                         vigorDeviceState_oid,
                                         OID_LENGTH(vigorDeviceState_oid),
                                         HANDLER_CAN_RONLY));
}

int
do_vigorIpAddress(netsnmp_mib_handler *handler,
                  netsnmp_handler_registration *reginfo,
                  netsnmp_agent_request_info *reqinfo,
                  netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;

    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_IPADDR;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                snmp_log(LOG_DEBUG,"%s:%d  process_snmpMsg error\r\n", __FUNCTION__, __LINE__);
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_vigorIpAddress)
            || (requests->requestvb->val_len > MAXSIZE_vigorIpAddress)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = NET_IPADDR;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_vigorSubnetMask(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_MASK;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_vigorSubnetMask)
            || (requests->requestvb->val_len > MAXSIZE_vigorSubnetMask)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = NET_MASK;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_vigorGateway(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_GATEWAY;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_vigorGateway)
            || (requests->requestvb->val_len > MAXSIZE_vigorGateway)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = NET_GATEWAY;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_vigorDBIpAddress(netsnmp_mib_handler *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_DB_IP;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_vigorDBIpAddress)
            || (requests->requestvb->val_len > MAXSIZE_vigorDBIpAddress)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = NET_DB_IP;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_vigorEquipmentType(netsnmp_mib_handler *handler,
                       netsnmp_handler_registration *reginfo,
                       netsnmp_agent_request_info *reqinfo,
                       netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = VIGOR_EQU_TYPE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_vigorSource(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_IPADDR;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                strcat(return_buf, ":161");
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len + 4);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_vigorDeviceState(netsnmp_mib_handler *handler,
                     netsnmp_handler_registration *reginfo,
                     netsnmp_agent_request_info *reqinfo,
                     netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetVigorDeviceState(return_buf))
            {
                return SNMP_ERR_GENERR;
            } 
            else*/ 
            {
                strcpy(return_buf, "reserve");
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

void
init_vt3308MIBObject(void)
{
    static oid      sccLdsIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 1, 0 };
    static oid      sccRqcIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 2, 0 };
    static oid      sccPstnIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 3, 0 };
    static oid      sccMgwIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 4, 0 };
    static oid      sccSlot1Port_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 5, 0 };
    static oid      sccSlot2Port_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 6, 0 };
    static oid      sccRssiThreshold_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 7, 0 };
    static oid      sccBufferLength_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 8, 0 };
    static oid      sccVersion_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 9, 0 };
    static oid      sccSlotNum_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 10, 0 };
    static oid      sccBusy_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 11, 0 };
    static oid      sccCaller_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 12, 0 };
    static oid      sccCalled_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 13, 0 };
    static oid      sccRtpIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 14, 0 };
    static oid      sccCallInfo_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 15, 0 };
    static oid      sccBtsIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 16, 0 };
    static oid      sccBtsState_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 17, 0 };
    static oid      sccLinkState_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 18, 0 };
    static oid      sccTalker_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 19, 0 };
    static oid      sccBSID_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 2, 1, 20, 0 };

    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("sccLdsIpAddress",
                               do_sccLdsIpAddress,
                               sccLdsIpAddress_oid,
                               OID_LENGTH(sccLdsIpAddress_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("sccRqcIpAddress",
                               do_sccRqcIpAddress,
                               sccRqcIpAddress_oid,
                               OID_LENGTH(sccRqcIpAddress_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("sccPstnIpAddress",
                               do_sccPstnIpAddress,
                               sccPstnIpAddress_oid,
                               OID_LENGTH(sccPstnIpAddress_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("sccMgwIpAddress",
                               do_sccMgwIpAddress,
                               sccMgwIpAddress_oid,
                               OID_LENGTH(sccMgwIpAddress_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("sccSlot1Port",
                               do_sccSlot1Port,
                               sccSlot1Port_oid,
                               OID_LENGTH(sccSlot1Port_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("sccSlot2Port",
                               do_sccSlot2Port,
                               sccSlot2Port_oid,
                               OID_LENGTH(sccSlot2Port_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("sccRssiThreshold",
                               do_sccRssiThreshold,
                               sccRssiThreshold_oid,
                               OID_LENGTH(sccRssiThreshold_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("sccBufferLength",
                               do_sccBufferLength,
                               sccBufferLength_oid,
                               OID_LENGTH(sccBufferLength_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccVersion",
                                         get_sccVersion,
                                         sccVersion_oid,
                                         OID_LENGTH(sccVersion_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccSlotNum",
                                         get_sccSlotNum,
                                         sccSlotNum_oid,
                                         OID_LENGTH(sccSlotNum_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccBusy",
                                         get_sccBusy,
                                         sccBusy_oid,
                                         OID_LENGTH(sccBusy_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccCaller",
                                         get_sccCaller,
                                         sccCaller_oid,
                                         OID_LENGTH(sccCaller_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccCalled",
                                         get_sccCalled,
                                         sccCalled_oid,
                                         OID_LENGTH(sccCalled_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccRtpIpAddress",
                                         get_sccRtpIpAddress,
                                         sccRtpIpAddress_oid,
                                         OID_LENGTH(sccRtpIpAddress_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccCallInfo",
                                         get_sccCallInfo,
                                         sccCallInfo_oid,
                                         OID_LENGTH(sccCallInfo_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccBtsIpAddress",
                                         get_sccBtsIpAddress,
                                         sccBtsIpAddress_oid,
                                         OID_LENGTH(sccBtsIpAddress_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccBtsState",
                                         get_sccBtsState,
                                         sccBtsState_oid,
                                         OID_LENGTH(sccBtsState_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccLinkState",
                                         get_sccLinkState,
                                         sccLinkState_oid,
                                         OID_LENGTH(sccLinkState_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccTalker",
                                         get_sccTalker,
                                         sccTalker_oid,
                                         OID_LENGTH(sccTalker_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("sccBSID",
                                         get_sccBSID,
                                         sccBSID_oid,
                                         OID_LENGTH(sccBSID_oid),
                                         HANDLER_CAN_RONLY));
}

int
do_sccLdsIpAddress(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_LDS_IP;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_sccLdsIpAddress)
            || (requests->requestvb->val_len > MAXSIZE_sccLdsIpAddress)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = NET_LDS_IP;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_sccRqcIpAddress(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_RQC_IP;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_sccRqcIpAddress)
            || (requests->requestvb->val_len > MAXSIZE_sccRqcIpAddress)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = NET_RQC_IP;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_sccPstnIpAddress(netsnmp_mib_handler *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = SCC_PSTN_IP;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_sccPstnIpAddress)
            || (requests->requestvb->val_len > MAXSIZE_sccPstnIpAddress)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = SCC_PSTN_IP;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_sccMgwIpAddress(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_MGW_IP;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_sccMgwIpAddress)
            || (requests->requestvb->val_len > MAXSIZE_sccMgwIpAddress)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = NET_MGW_IP;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_sccSlot1Port(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_PORT_S1;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                         (u_char *) return_buf,
                                         var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_sccSlot1Port)
            || (requests->requestvb->val_len > MAXSIZE_sccSlot1Port)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_PORT_S1;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_sccSlot2Port(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_PORT_S2;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                         (u_char *) return_buf,
                                         var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_sccSlot2Port)
            || (requests->requestvb->val_len > MAXSIZE_sccSlot2Port)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_PORT_S2;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_sccRssiThreshold(netsnmp_mib_handler *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = SCC_RSSI_THRS;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                         (u_char *) return_buf,
                                         var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_sccRssiThreshold)
            || (requests->requestvb->val_len > MAXSIZE_sccRssiThreshold)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = SCC_RSSI_THRS;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_sccBufferLength(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = SCC_BUF_LEN;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                         (u_char *) return_buf,
                                         var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_sccBufferLength)
            || (requests->requestvb->val_len > MAXSIZE_sccBufferLength)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = SCC_BUF_LEN;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccVersion(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = SCC_VERSION;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                         (u_char *) return_buf,
                                         var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccSlotNum(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccSlotNum(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccBusy(netsnmp_mib_handler *handler,
            netsnmp_handler_registration *reginfo,
            netsnmp_agent_request_info *reqinfo,
            netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccBusy(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccCaller(netsnmp_mib_handler *handler,
              netsnmp_handler_registration *reginfo,
              netsnmp_agent_request_info *reqinfo,
              netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccCaller(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccCalled(netsnmp_mib_handler *handler,
              netsnmp_handler_registration *reginfo,
              netsnmp_agent_request_info *reqinfo,
              netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccCalled(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccRtpIpAddress(netsnmp_mib_handler *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccRtpIpAddress(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccCallInfo(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccCallInfo(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccBtsIpAddress(netsnmp_mib_handler *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccBtsIpAddress(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccBtsState(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccBtsState(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccLinkState(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = LINK_STATE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                         (u_char *) return_buf,
                                         var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccTalker(netsnmp_mib_handler *handler,
              netsnmp_handler_registration *reginfo,
              netsnmp_agent_request_info *reqinfo,
              netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccTalker(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_sccBSID(netsnmp_mib_handler *handler,
              netsnmp_handler_registration *reginfo,
              netsnmp_agent_request_info *reqinfo,
              netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetSccTalker(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

void
init_vt3830MIBObject(void)
{
    static oid      btsTxFreq_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 1, 0 };
    static oid      btsRxFreq_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 2, 0 };
    static oid      btsTxPower_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 3, 0 };
    static oid      btsSquelchLevel_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 4, 0 };
    static oid      btsMode_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 5, 0 };
    static oid      btsBand_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 6, 0 };
    static oid      btsDelayPar_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 7, 0 };
    static oid      btsSlot1Port_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 8, 0 };
    static oid      btsSlot2Port_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 9, 0 };
    static oid      btsSccIpAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 10, 0 };
    static oid      btsModel_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 11, 0 };
    static oid      btsEsn_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 12, 0 };
    static oid      btsHwVersion_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 13, 0 };
    static oid      btsSwVersion_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 14, 0 };
    static oid      btsRealTxPower_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 15, 0 };
    static oid      btsVswr_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 16, 0 };
    static oid      btsRssi_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 17, 0 };
    static oid      btsEnvirTemperature_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 18, 0 };
    static oid      btsPaTemperature_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 19, 0 };
    static oid      btsDcVoltage_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 20, 0 };
    static oid      btsBatVoltage_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 21, 0 };
    static oid      btsFanSpeed_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 22, 0 };
    static oid      btsMacAddress_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 23, 0 };
    static oid      btsAlarmState_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 24, 0 };
    static oid      btsLinkState_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 25, 0 };
    static oid      btsExtClock_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 26, 0 };
    static oid      btsTxState_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 27, 0 };
    static oid      btsFaultMode_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 28, 0 };
	static oid      btsSquelchMode_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 29, 0 };
	static oid      btsRxcss_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 30, 0 };
	static oid      btsTxcss_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 31, 0 };
	static oid      btsCc_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 32, 0 };
	static oid      btsDevEnable_oid[] =
        { 1, 3, 6, 1, 4, 1, 259, 1, 1, 1, 33, 0 };

    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsTxFreq",
                               do_btsTxFreq,
                               btsTxFreq_oid,
                               OID_LENGTH(btsTxFreq_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsRxFreq",
                               do_btsRxFreq,
                               btsRxFreq_oid,
                               OID_LENGTH(btsRxFreq_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsTxPower",
                               do_btsTxPower,
                               btsTxPower_oid,
                               OID_LENGTH(btsTxPower_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsSquelchLevel",
                               do_btsSquelchLevel,
                               btsSquelchLevel_oid,
                               OID_LENGTH(btsSquelchLevel_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsMode",
                               do_btsMode,
                               btsMode_oid,
                               OID_LENGTH(btsMode_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsBand",
                               do_btsBand,
                               btsBand_oid,
                               OID_LENGTH(btsBand_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsDelayPar",
                               do_btsDelayPar,
                               btsDelayPar_oid,
                               OID_LENGTH(btsDelayPar_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsSlot1Port",
                               do_btsSlot1Port,
                               btsSlot1Port_oid,
                               OID_LENGTH(btsSlot1Port_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsSlot2Port",
                               do_btsSlot2Port,
                               btsSlot2Port_oid,
                               OID_LENGTH(btsSlot2Port_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsSccIpAddress",
                               do_btsSccIpAddress,
                               btsSccIpAddress_oid,
                               OID_LENGTH(btsSccIpAddress_oid),
                               HANDLER_CAN_RWRITE));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsModel",
                                         get_btsModel,
                                         btsModel_oid,
                                         OID_LENGTH(btsModel_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsEsn",
                                         get_btsEsn,
                                         btsEsn_oid,
                                         OID_LENGTH(btsEsn_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsHwVersion",
                                         get_btsHwVersion,
                                         btsHwVersion_oid,
                                         OID_LENGTH(btsHwVersion_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsSwVersion",
                                         get_btsSwVersion,
                                         btsSwVersion_oid,
                                         OID_LENGTH(btsSwVersion_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsRealTxPower",
                                         get_btsRealTxPower,
                                         btsRealTxPower_oid,
                                         OID_LENGTH(btsRealTxPower_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsVswr",
                                         get_btsVswr,
                                         btsVswr_oid,
                                         OID_LENGTH(btsVswr_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsRssi",
                                         get_btsRssi,
                                         btsRssi_oid,
                                         OID_LENGTH(btsRssi_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsEnvirTemperature",
                                         get_btsEnvirTemperature,
                                         btsEnvirTemperature_oid,
                                         OID_LENGTH
                                         (btsEnvirTemperature_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsPaTemperature",
                                         get_btsPaTemperature,
                                         btsPaTemperature_oid,
                                         OID_LENGTH(btsPaTemperature_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsDcVoltage", get_btsDcVoltage,
                                         btsDcVoltage_oid,
                                         OID_LENGTH(btsDcVoltage_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsBatVoltage",
                                         get_btsBatVoltage,
                                         btsBatVoltage_oid,
                                         OID_LENGTH(btsBatVoltage_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsFanSpeed", get_btsFanSpeed,
                                         btsFanSpeed_oid,
                                         OID_LENGTH(btsFanSpeed_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsMacAddress",
                                         get_btsMacAddress,
                                         btsMacAddress_oid,
                                         OID_LENGTH(btsMacAddress_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsAlarmState",
                                         get_btsAlarmState,
                                         btsAlarmState_oid,
                                         OID_LENGTH(btsAlarmState_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsLinkState", get_btsLinkState,
                                         btsLinkState_oid,
                                         OID_LENGTH(btsLinkState_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsExtClock", get_btsExtClock,
                                         btsExtClock_oid,
                                         OID_LENGTH(btsExtClock_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("btsTxState", get_btsTxState,
                                         btsTxState_oid,
                                         OID_LENGTH(btsTxState_oid),
                                         HANDLER_CAN_RONLY));
    netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsFaultMode",
                               do_btsFaultMode,
                               btsFaultMode_oid,
                               OID_LENGTH(btsFaultMode_oid),
                               HANDLER_CAN_RWRITE));
	netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsSquelchMode",
                               do_btsSquelchMode,
                               btsSquelchMode_oid,
                               OID_LENGTH(btsSquelchMode_oid),
                               HANDLER_CAN_RWRITE));
	netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsRxcss",
                               do_btsRxcss,
                               btsRxcss_oid,
                               OID_LENGTH(btsRxcss_oid),
                               HANDLER_CAN_RWRITE));
	netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsTxcss",
                               do_btsTxcss,
                               btsTxcss_oid,
                               OID_LENGTH(btsTxcss_oid),
                               HANDLER_CAN_RWRITE));
	netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsCc",
                               do_btsCc,
                               btsCc_oid,
                               OID_LENGTH(btsCc_oid),
                               HANDLER_CAN_RWRITE));
	netsnmp_register_instance(netsnmp_create_handler_registration
                              ("btsDevEnable",
                               do_btsDevEnable,
                               btsDevEnable_oid,
                               OID_LENGTH(btsDevEnable_oid),
                               HANDLER_CAN_RWRITE));
}

int
do_btsTxFreq(netsnmp_mib_handler *handler,
             netsnmp_handler_registration *reginfo,
             netsnmp_agent_request_info *reqinfo,
             netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_TX_FREQ;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsTxFreq)
            || (requests->requestvb->val_len > MAXSIZE_btsTxFreq)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_TX_FREQ;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsRxFreq(netsnmp_mib_handler *handler,
             netsnmp_handler_registration *reginfo,
             netsnmp_agent_request_info *reqinfo,
             netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_RX_FREQ;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsRxFreq)
            || (requests->requestvb->val_len > MAXSIZE_btsRxFreq)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_RX_FREQ;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsTxPower(netsnmp_mib_handler *handler,
              netsnmp_handler_registration *reginfo,
              netsnmp_agent_request_info *reqinfo,
              netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_TX_POWER;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsTxPower)
            || (requests->requestvb->val_len > MAXSIZE_btsTxPower)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_TX_POWER;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsSquelchLevel(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_SQUELCH;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsSquelchLevel)
            || (requests->requestvb->val_len > MAXSIZE_btsSquelchLevel)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_SQUELCH;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsMode(netsnmp_mib_handler *handler,
           netsnmp_handler_registration *reginfo,
           netsnmp_agent_request_info *reqinfo,
           netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_CH_MODE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsMode)
            || (requests->requestvb->val_len > MAXSIZE_btsMode)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_CH_MODE;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsBand(netsnmp_mib_handler *handler,
           netsnmp_handler_registration *reginfo,
           netsnmp_agent_request_info *reqinfo,
           netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_CH_BAND;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsBand)
            || (requests->requestvb->val_len > MAXSIZE_btsBand)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_CH_BAND;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsDelayPar(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_TIME_DELAY;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsDelayPar)
            || (requests->requestvb->val_len > MAXSIZE_btsDelayPar)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_TIME_DELAY;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsSlot1Port(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_PORT_S1;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                         (u_char *) return_buf,
                                         var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsSlot1Port)
            || (requests->requestvb->val_len > MAXSIZE_btsSlot1Port)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_PORT_S1;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsSlot2Port(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_PORT_S2;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                         (u_char *) return_buf,
                                         var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsSlot2Port)
            || (requests->requestvb->val_len > MAXSIZE_btsSlot2Port)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_PORT_S2;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsSccIpAddress(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_SC_IP;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                snmp_log(LOG_DEBUG,"%s:%d  process_snmpMsg error\r\n", __FUNCTION__, __LINE__);
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsSccIpAddress)
            || (requests->requestvb->val_len > MAXSIZE_btsSccIpAddress)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = NET_SC_IP;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsModel(netsnmp_mib_handler *handler,
             netsnmp_handler_registration *reginfo,
             netsnmp_agent_request_info *reqinfo,
             netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_MODEL;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsEsn(netsnmp_mib_handler *handler,
           netsnmp_handler_registration *reginfo,
           netsnmp_agent_request_info *reqinfo,
           netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_ESN;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsHwVersion(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_HW_VER;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsSwVersion(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_FW_VER;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsRealTxPower(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_REAL_TX_POWER;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsVswr(netsnmp_mib_handler *handler,
            netsnmp_handler_registration *reginfo,
            netsnmp_agent_request_info *reqinfo,
            netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_VSWR;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsRssi(netsnmp_mib_handler *handler,
            netsnmp_handler_registration *reginfo,
            netsnmp_agent_request_info *reqinfo,
            netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_RSSI;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsEnvirTemperature(netsnmp_mib_handler *handler,
                        netsnmp_handler_registration *reginfo,
                        netsnmp_agent_request_info *reqinfo,
                        netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_ENV_TEMP;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsPaTemperature(netsnmp_mib_handler *handler,
                     netsnmp_handler_registration *reginfo,
                     netsnmp_agent_request_info *reqinfo,
                     netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_PA_TEMP;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsDcVoltage(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_DC_VOLT;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsBatVoltage(netsnmp_mib_handler *handler,
                  netsnmp_handler_registration *reginfo,
                  netsnmp_agent_request_info *reqinfo,
                  netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_BAT_VOLT;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsFanSpeed(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_FAN_RPM;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsMacAddress(netsnmp_mib_handler *handler,
                  netsnmp_handler_registration *reginfo,
                  netsnmp_agent_request_info *reqinfo,
                  netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = NET_MAC;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsAlarmState(netsnmp_mib_handler *handler,
                  netsnmp_handler_registration *reginfo,
                  netsnmp_agent_request_info *reqinfo,
                  netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = ALARM_STATE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsLinkState(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = LINK_STATE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsExtClock(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = EXTCLK_STATE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
get_btsTxState(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            /*
             * get from core layer
             
            if (!XXX_MGR_GetBtsTxState(return_buf))
                ? ? ? {
                return SNMP_ERR_GENERR;
            } else {
                var_len = strlen(return_buf);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }*/

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsFaultMode(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_FAULT_MODE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                snmp_log(LOG_DEBUG,"%s:%d  process_snmpMsg error\r\n", __FUNCTION__, __LINE__);
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsFaultMode)
            || (requests->requestvb->val_len > MAXSIZE_btsFaultMode)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_FAULT_MODE;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsSquelchMode(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_SQUELCH_MODE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                snmp_log(LOG_DEBUG,"%s:%d  process_snmpMsg error\r\n", __FUNCTION__, __LINE__);
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsSquelchMode)
            || (requests->requestvb->val_len > MAXSIZE_btsSquelchMode)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_SQUELCH_MODE;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsRxcss(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_RX_CSS;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                snmp_log(LOG_DEBUG,"%s:%d  process_snmpMsg error\r\n", __FUNCTION__, __LINE__);
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsRxcss)
            || (requests->requestvb->val_len > MAXSIZE_btsRxcss)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_RX_CSS;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsTxcss(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_TX_CSS;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                snmp_log(LOG_DEBUG,"%s:%d  process_snmpMsg error\r\n", __FUNCTION__, __LINE__);
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsTxcss)
            || (requests->requestvb->val_len > MAXSIZE_btsTxcss)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_TX_CSS;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsCc(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_CC;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                snmp_log(LOG_DEBUG,"%s:%d  process_snmpMsg error\r\n", __FUNCTION__, __LINE__);
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsCc)
            || (requests->requestvb->val_len > MAXSIZE_btsCc)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_CC;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
do_btsDevEnable(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;
            
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = BTS_DEV_ENABLE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                snmp_log(LOG_DEBUG,"%s:%d  process_snmpMsg error\r\n", __FUNCTION__, __LINE__);
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

        /*
         * SET REQUEST
         * *
         * * multiple states in the transaction.  See:
         * * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
    case MODE_SET_RESERVE1:
        /*
         * check type and length
         */
        if (requests->requestvb->type != ASN_OCTET_STR) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGTYPE);
            return SNMP_ERR_NOERROR;
        }

        if ((requests->requestvb->val_len < MINSIZE_btsDevEnable)
            || (requests->requestvb->val_len > MAXSIZE_btsDevEnable)) {
            netsnmp_set_request_error(reqinfo, requests,
                                      SNMP_ERR_WRONGLENGTH);
            return SNMP_ERR_NOERROR;
        }

        break;

    case MODE_SET_RESERVE2:

        break;

    case MODE_SET_FREE:
        /*
         * XXX: free resources allocated in RESERVE1 and/or
         * * RESERVE2.  Something failed somewhere, and the states
         * * below won't be called.
         */
        break;

    case MODE_SET_ACTION:
        {
            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_SET;
            queue_msg.snmp_msg.oper_code = BTS_DEV_ENABLE;

            /*
             * get user value
             */
            memcpy(queue_msg.snmp_msg.u_data.msg_data_str, requests->requestvb->val.string,
                   requests->requestvb->val_len);
            queue_msg.snmp_msg.u_data.msg_data_str[requests->requestvb->val_len] = '\0';

            /*
             * set to core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_COMMITFAILED);
                return SNMP_ERR_NOERROR;
            }

            break;
        }

    case MODE_SET_COMMIT:
        break;

    case MODE_SET_UNDO:
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}


int
get_cddWorkMode(netsnmp_mib_handler *handler,
             netsnmp_handler_registration *reginfo,
             netsnmp_agent_request_info *reqinfo,
             netsnmp_request_info *requests)
{
    QUEUE_MSG_T queue_msg;
    /*
     * dispatch get vs. set
     */
    switch (reqinfo->mode) {
        /*
         * GET REQUEST
         */
    case MODE_GET:
        {
            unsigned long          var_len = 0;

            memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
            queue_msg.msg_type = CMD_GET;
            queue_msg.snmp_msg.oper_code = CLK_DISTRIBUTE_MODE;

            /*
             * get from core layer
             */
            if (process_snmpMsg(&queue_msg) != MSG_OK)
            {
                return SNMP_ERR_GENERR;
            } 
            else 
            {
                var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
                memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
                snmp_set_var_typed_value(requests->requestvb,
                                         ASN_OCTET_STR,
                                         (u_char *) return_buf, var_len);
            }

            break;
        }

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

  
 int
 get_cddAPPVer(netsnmp_mib_handler *handler,
			  netsnmp_handler_registration *reginfo,
			  netsnmp_agent_request_info *reqinfo,
			  netsnmp_request_info *requests)
 {
	 QUEUE_MSG_T queue_msg;
	 /*
	  * dispatch get vs. set
	  */
	 switch (reqinfo->mode) {
		 /*
		  * GET REQUEST
		  */
	 case MODE_GET:
		 {
			 unsigned long			var_len = 0;
 
			 memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
			 queue_msg.msg_type = CMD_GET;
			 queue_msg.snmp_msg.oper_code = CLK_DISTRIBUTE_APP_VER;
 
			 /*
			  * get from core layer
			  */
			 if (process_snmpMsg(&queue_msg) != MSG_OK)
			 {
				 return SNMP_ERR_GENERR;
			 } 
			 else 
			 {
				 var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
				 memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
				 snmp_set_var_typed_value(requests->requestvb,
										  ASN_OCTET_STR,
										  (u_char *) return_buf, var_len);
			 }
 
			 break;
		 }
 
	 default:
		 return SNMP_ERR_GENERR;
	 }
 
	 return SNMP_ERR_NOERROR;
 }
 
 
 int
 get_cddFPGAVer(netsnmp_mib_handler *handler,
			  netsnmp_handler_registration *reginfo,
			  netsnmp_agent_request_info *reqinfo,
			  netsnmp_request_info *requests)
 {
	 QUEUE_MSG_T queue_msg;
	 /*
	  * dispatch get vs. set
	  */
	 switch (reqinfo->mode) {
		 /*
		  * GET REQUEST
		  */
	 case MODE_GET:
		 {
			 unsigned long			var_len = 0;
 
			 memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
			 queue_msg.msg_type = CMD_GET;
			 queue_msg.snmp_msg.oper_code = CLK_DISTRIBUTE_FPGA_VER;
 
			 /*
			  * get from core layer
			  */
			 if (process_snmpMsg(&queue_msg) != MSG_OK)
			 {
				 return SNMP_ERR_GENERR;
			 } 
			 else 
			 {
				 var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
				 memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
				 snmp_set_var_typed_value(requests->requestvb,
										  ASN_OCTET_STR,
										  (u_char *) return_buf, var_len);
			 }
 
			 break;
		 }
 
	 default:
		 return SNMP_ERR_GENERR;
	 }
 
	 return SNMP_ERR_NOERROR;
 }

  
  
  
  int
  get_cddHwVer(netsnmp_mib_handler *handler,
			   netsnmp_handler_registration *reginfo,
			   netsnmp_agent_request_info *reqinfo,
			   netsnmp_request_info *requests)
  {
	  QUEUE_MSG_T queue_msg;
	  /*
	   * dispatch get vs. set
	   */
	  switch (reqinfo->mode) {
		  /*
		   * GET REQUEST
		   */
	  case MODE_GET:
		  {
			  unsigned long 		 var_len = 0;
  
			  memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
			  queue_msg.msg_type = CMD_GET;
			  queue_msg.snmp_msg.oper_code = CLK_DISTRIBUTE_HW_VER;
  
			  /*
			   * get from core layer
			   */
			  if (process_snmpMsg(&queue_msg) != MSG_OK)
			  {
				  return SNMP_ERR_GENERR;
			  } 
			  else 
			  {
				  var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
				  memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
				  snmp_set_var_typed_value(requests->requestvb,
										   ASN_OCTET_STR,
										   (u_char *) return_buf, var_len);
			  }
  
			  break;
		  }
  
	  default:
		  return SNMP_ERR_GENERR;
	  }
  
	  return SNMP_ERR_NOERROR;
  }


int
get_cddFPGAstat(netsnmp_mib_handler *handler,
			netsnmp_handler_registration *reginfo,
			netsnmp_agent_request_info *reqinfo,
			netsnmp_request_info *requests)
{
   QUEUE_MSG_T queue_msg;
   /*
	* dispatch get vs. set
	*/
   switch (reqinfo->mode) {
	   /*
		* GET REQUEST
		*/
   case MODE_GET:
	   {
		   unsigned long		  var_len = 0;

		   memset(&queue_msg, 0, sizeof(QUEUE_MSG_T));
		   queue_msg.msg_type = CMD_GET;
		   queue_msg.snmp_msg.oper_code = CLK_DISTRIBUTE_FPGA_STATE;

		   /*
			* get from core layer
			*/
		   if (process_snmpMsg(&queue_msg) != MSG_OK)
		   {
			   return SNMP_ERR_GENERR;
		   } 
		   else 
		   {
			   var_len = strlen(queue_msg.snmp_msg.u_data.msg_data_str);
			   memcpy(return_buf, queue_msg.snmp_msg.u_data.msg_data_str, var_len);
			   snmp_set_var_typed_value(requests->requestvb,
										ASN_OCTET_STR,
										(u_char *) return_buf, var_len);
		   }

		   break;
	   }

   default:
	   return SNMP_ERR_GENERR;
   }

   return SNMP_ERR_NOERROR;
}




void
init_vt3888MIBObject(void)
{
	static oid	   cddWorkMode_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 1, 0 };
	static oid	   cddAppVer_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 2, 0 };
	static oid	   cddFPGAVer_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 3, 0 };
	static oid	   cddHwVer_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 4, 0 };
	static oid	   cddFPGAstat_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 5, 0 };

	static oid	   cddGPSClkSource_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 6, 0 };
	static oid	   cddPTPClkSource_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 7, 0 };
	static oid	   cddGPSLockState_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 8, 0 };
	static oid	   cddPTPLockState_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 9, 0 };

	   
	static oid	   cddFPGATime_oid[] =
	   { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 10, 0 };
	static oid		cddGPSTime_oid[] =
		{ 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 11, 0 };
	static oid		cddOMAPTime_oid[] =
		{ 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 12, 0 };
	static oid		cddPHYTime_oid[] =
		{ 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 13, 0 };
	static oid		 cddSys2PHY_oid[] =
		 { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 14, 0 };
	static oid		 cddPHY2Sys_oid[] =
		 { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 15, 0 };
	static oid		 cddSecondPulse_oid[] =
		 { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 16, 0 };
	static oid		 cddNetlink_oid[] =
		 { 1, 3, 6, 1, 4, 1, 259, 1, 4, 1, 17, 0 };

   netsnmp_register_instance(netsnmp_create_handler_registration
							 ("cddworkMode",
							  get_cddWorkMode,
							  cddWorkMode_oid,
							  OID_LENGTH(cddWorkMode_oid),
							  HANDLER_CAN_RONLY));
   
   netsnmp_register_instance(netsnmp_create_handler_registration
							   ("cddAPPVer",
							   get_cddAPPVer,
							   cddAppVer_oid,
							   OID_LENGTH(cddAppVer_oid),
							   HANDLER_CAN_RONLY));

	netsnmp_register_instance(netsnmp_create_handler_registration
								("cddFPGAVer",
								get_cddFPGAVer,
								cddFPGAVer_oid,
								OID_LENGTH(cddFPGAVer_oid),
								HANDLER_CAN_RONLY));
	netsnmp_register_instance(netsnmp_create_handler_registration
								("cddHwVer",
								get_cddHwVer,
								cddHwVer_oid,
								OID_LENGTH(cddHwVer_oid),
								HANDLER_CAN_RONLY));

	netsnmp_register_instance(netsnmp_create_handler_registration
							   ("cddFPGAstat",
							   get_cddFPGAstat,
							   cddFPGAstat_oid,
							   OID_LENGTH(cddFPGAstat_oid),
							   HANDLER_CAN_RONLY)); 		
  
}

