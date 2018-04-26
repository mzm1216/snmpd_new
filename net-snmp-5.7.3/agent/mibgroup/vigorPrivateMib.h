/*
 * Note: this file originally edit by lei.deng
 * 
 */
#ifndef VIGORPRIVATEMIB_H
#define VIGORPRIVATEMIB_H

/*
 * function declarations
 */
void            init_vigorPubMIBObject(void);
Netsnmp_Node_Handler do_vigorIpAddress;
Netsnmp_Node_Handler do_vigorSubnetMask;
Netsnmp_Node_Handler do_vigorGateway;
Netsnmp_Node_Handler do_vigorDBIpAddress;
Netsnmp_Node_Handler get_vigorEquipmentType;
Netsnmp_Node_Handler get_vigorSource;
Netsnmp_Node_Handler get_vigorDeviceState;

#define LEAF_vigorIpAddress   1
#define MINSIZE_vigorIpAddress  0L
#define MAXSIZE_vigorIpAddress  128L
#define LEAF_vigorSubnetMask   2
#define MINSIZE_vigorSubnetMask  0L
#define MAXSIZE_vigorSubnetMask  128L
#define LEAF_vigorGateway   3
#define MINSIZE_vigorGateway  0L
#define MAXSIZE_vigorGateway  128L
#define LEAF_vigorDBIpAddress   4
#define MINSIZE_vigorDBIpAddress  0L
#define MAXSIZE_vigorDBIpAddress  128L
#define LEAF_vigorEquipmentType   5
#define MINSIZE_vigorEquipmentType  0L
#define MAXSIZE_vigorEquipmentType  128L
#define LEAF_vigorSource   6
#define MINSIZE_vigorSource  0L
#define MAXSIZE_vigorSource  128L
#define LEAF_vigorDeviceState   7
#define MINSIZE_vigorDeviceState  0L
#define MAXSIZE_vigorDeviceState  128L

void            init_vt3308MIBObject(void);
Netsnmp_Node_Handler do_sccLdsIpAddress;
Netsnmp_Node_Handler do_sccRqcIpAddress;
Netsnmp_Node_Handler do_sccPstnIpAddress;
Netsnmp_Node_Handler do_sccMgwIpAddress;
Netsnmp_Node_Handler do_sccSlot1Port;
Netsnmp_Node_Handler do_sccSlot2Port;
Netsnmp_Node_Handler do_sccRssiThreshold;
Netsnmp_Node_Handler do_sccBufferLength;
Netsnmp_Node_Handler get_sccVersion;
Netsnmp_Node_Handler get_sccSlotNum;
Netsnmp_Node_Handler get_sccBusy;
Netsnmp_Node_Handler get_sccCaller;
Netsnmp_Node_Handler get_sccCalled;
Netsnmp_Node_Handler get_sccRtpIpAddress;
Netsnmp_Node_Handler get_sccCallInfo;
Netsnmp_Node_Handler get_sccBtsIpAddress;
Netsnmp_Node_Handler get_sccBtsState;
Netsnmp_Node_Handler get_sccLinkState;
Netsnmp_Node_Handler get_sccTalker;
Netsnmp_Node_Handler get_sccBSID;

#define LEAF_sccLdsIpAddress   1
#define MINSIZE_sccLdsIpAddress  0L
#define MAXSIZE_sccLdsIpAddress  128L
#define LEAF_sccRqcIpAddress   2
#define MINSIZE_sccRqcIpAddress  0L
#define MAXSIZE_sccRqcIpAddress  128L
#define LEAF_sccPstnIpAddress   3
#define MINSIZE_sccPstnIpAddress  0L
#define MAXSIZE_sccPstnIpAddress  128L
#define LEAF_sccMgwIpAddress   4
#define MINSIZE_sccMgwIpAddress  0L
#define MAXSIZE_sccMgwIpAddress  128L
#define LEAF_sccSlot1Port   5
#define MINSIZE_sccSlot1Port  0L
#define MAXSIZE_sccSlot1Port  128L
#define LEAF_sccSlot2Port   6
#define MINSIZE_sccSlot2Port  0L
#define MAXSIZE_sccSlot2Port  128L
#define LEAF_sccRssiThreshold   7
#define MINSIZE_sccRssiThreshold  0L
#define MAXSIZE_sccRssiThreshold  128L
#define LEAF_sccBufferLength   8
#define MINSIZE_sccBufferLength  0L
#define MAXSIZE_sccBufferLength  128L
#define LEAF_sccVersion   9
#define MINSIZE_sccVersion  0L
#define MAXSIZE_sccVersion  128L
#define LEAF_sccSlotNum   10
#define MINSIZE_sccSlotNum  0L
#define MAXSIZE_sccSlotNum  128L
#define LEAF_sccBusy   11
#define MINSIZE_sccBusy  0L
#define MAXSIZE_sccBusy  128L
#define LEAF_sccCaller   12
#define MINSIZE_sccCaller  0L
#define MAXSIZE_sccCaller  128L
#define LEAF_sccCalled   13
#define MINSIZE_sccCalled  0L
#define MAXSIZE_sccCalled  128L
#define LEAF_sccRtpIpAddress   14
#define MINSIZE_sccRtpIpAddress  0L
#define MAXSIZE_sccRtpIpAddress  128L
#define LEAF_sccCallInfo   15
#define MINSIZE_sccCallInfo  0L
#define MAXSIZE_sccCallInfo  128L
#define LEAF_sccBtsIpAddress   16
#define MINSIZE_sccBtsIpAddress  0L
#define MAXSIZE_sccBtsIpAddress  128L
#define LEAF_sccBtsState   17
#define MINSIZE_sccBtsState  0L
#define MAXSIZE_sccBtsState  128L
#define LEAF_sccLinkState   18
#define MINSIZE_sccLinkState  0L
#define MAXSIZE_sccLinkState  128L
#define LEAF_sccTalker   19
#define MINSIZE_sccTalker  0L
#define MAXSIZE_sccTalker  128L

void            init_vt3830MIBObject(void);
Netsnmp_Node_Handler do_btsTxFreq;
Netsnmp_Node_Handler do_btsRxFreq;
Netsnmp_Node_Handler do_btsTxPower;
Netsnmp_Node_Handler do_btsSquelchLevel;
Netsnmp_Node_Handler do_btsMode;
Netsnmp_Node_Handler do_btsBand;
Netsnmp_Node_Handler do_btsDelayPar;
Netsnmp_Node_Handler do_btsSlot1Port;
Netsnmp_Node_Handler do_btsSlot2Port;
Netsnmp_Node_Handler do_btsSccIpAddress;
Netsnmp_Node_Handler get_btsModel;
Netsnmp_Node_Handler get_btsEsn;
Netsnmp_Node_Handler get_btsHwVersion;
Netsnmp_Node_Handler get_btsSwVersion;
Netsnmp_Node_Handler get_btsRealTxPower;
Netsnmp_Node_Handler get_btsVswr;
Netsnmp_Node_Handler get_btsRssi;
Netsnmp_Node_Handler get_btsEnvirTemperature;
Netsnmp_Node_Handler get_btsPaTemperature;
Netsnmp_Node_Handler get_btsDcVoltage;
Netsnmp_Node_Handler get_btsBatVoltage;
Netsnmp_Node_Handler get_btsFanSpeed;
Netsnmp_Node_Handler get_btsMacAddress;
Netsnmp_Node_Handler get_btsAlarmState;
Netsnmp_Node_Handler get_btsLinkState;
Netsnmp_Node_Handler get_btsExtClock;
Netsnmp_Node_Handler get_btsTxState;
Netsnmp_Node_Handler do_btsFaultMode;
Netsnmp_Node_Handler do_btsSquelchMode;
Netsnmp_Node_Handler do_btsRxcss;
Netsnmp_Node_Handler do_btsTxcss;
Netsnmp_Node_Handler do_btsCc;
Netsnmp_Node_Handler do_btsDevEnable;

#define LEAF_btsTxFreq   1
#define MINSIZE_btsTxFreq  0L
#define MAXSIZE_btsTxFreq  128L
#define LEAF_btsRxFreq   2
#define MINSIZE_btsRxFreq  0L
#define MAXSIZE_btsRxFreq  128L
#define LEAF_btsTxPower   3
#define MINSIZE_btsTxPower  0L
#define MAXSIZE_btsTxPower  128L
#define LEAF_btsSquelchLevel   4
#define MINSIZE_btsSquelchLevel  0L
#define MAXSIZE_btsSquelchLevel  128L
#define LEAF_btsMode   5
#define MINSIZE_btsMode  0L
#define MAXSIZE_btsMode  128L
#define LEAF_btsBand   6
#define MINSIZE_btsBand  0L
#define MAXSIZE_btsBand  128L
#define LEAF_btsDelayPar   7
#define MINSIZE_btsDelayPar  0L
#define MAXSIZE_btsDelayPar  128L
#define LEAF_btsSlot1Port   8
#define MINSIZE_btsSlot1Port  0L
#define MAXSIZE_btsSlot1Port  128L
#define LEAF_btsSlot2Port   9
#define MINSIZE_btsSlot2Port  0L
#define MAXSIZE_btsSlot2Port  128L
#define LEAF_btsSccIpAddress   10
#define MINSIZE_btsSccIpAddress  0L
#define MAXSIZE_btsSccIpAddress  128L
#define LEAF_btsModel   11
#define MINSIZE_btsModel  0L
#define MAXSIZE_btsModel  128L
#define LEAF_btsEsn   12
#define MINSIZE_btsEsn  0L
#define MAXSIZE_btsEsn  128L
#define LEAF_btsHwVersion   13
#define MINSIZE_btsHwVersion  0L
#define MAXSIZE_btsHwVersion  128L
#define LEAF_btsSwVersion   14
#define MINSIZE_btsSwVersion  0L
#define MAXSIZE_btsSwVersion  128L
#define LEAF_btsRealTxPower   15
#define MINSIZE_btsRealTxPower  0L
#define MAXSIZE_btsRealTxPower  128L
#define LEAF_btsVswr   16
#define MINSIZE_btsVswr  0L
#define MAXSIZE_btsVswr  128L
#define LEAF_btsRssi   17
#define MINSIZE_btsRssi  0L
#define MAXSIZE_btsRssi  128L
#define LEAF_btsEnvirTemperature   18
#define MINSIZE_btsEnvirTemperature  0L
#define MAXSIZE_btsEnvirTemperature  128L
#define LEAF_btsPaTemperature   19
#define MINSIZE_btsPaTemperature  0L
#define MAXSIZE_btsPaTemperature  128L
#define LEAF_btsDcVoltage   20
#define MINSIZE_btsDcVoltage  0L
#define MAXSIZE_btsDcVoltage  128L
#define LEAF_btsBatVoltage   21
#define MINSIZE_btsBatVoltage  0L
#define MAXSIZE_btsBatVoltage  128L
#define LEAF_btsFanSpeed   22
#define MINSIZE_btsFanSpeed  0L
#define MAXSIZE_btsFanSpeed  128L
#define LEAF_btsMacAddress   23
#define MINSIZE_btsMacAddress  0L
#define MAXSIZE_btsMacAddress  128L
#define LEAF_btsAlarmState   24
#define MINSIZE_btsAlarmState  0L
#define MAXSIZE_btsAlarmState  128L
#define LEAF_btsLinkState   25
#define MINSIZE_btsLinkState  0L
#define MAXSIZE_btsLinkState  128L
#define LEAF_btsExtClock   26
#define MINSIZE_btsExtClock  0L
#define MAXSIZE_btsExtClock  128L
#define LEAF_btsTxState   27
#define MINSIZE_btsTxState  0L
#define MAXSIZE_btsTxState  128L
#define LEAF_btsFaultMode   28
#define MINSIZE_btsFaultMode  0L
#define MAXSIZE_btsFaultMode  128L
#define MINSIZE_btsSquelchMode  0L
#define MAXSIZE_btsSquelchMode  128L
#define MINSIZE_btsRxcss  0L
#define MAXSIZE_btsRxcss  128L
#define MINSIZE_btsTxcss  0L
#define MAXSIZE_btsTxcss  128L
#define MINSIZE_btsCc  0L
#define MAXSIZE_btsCc  128L
#define MINSIZE_btsDevEnable  0L
#define MAXSIZE_btsDevEnable  128L

#endif                          /* VIGORPRIVATEMIB_H */
