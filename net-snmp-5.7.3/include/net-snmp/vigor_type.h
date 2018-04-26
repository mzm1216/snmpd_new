#ifndef VIGOR_TYPE_H
#define VIGOR_TYPE_H

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <string.h>
#include <sys/msg.h>
#include <pthread.h>

#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif

/*
 * message queue
 */
#define MAX_SIZE         	256
#define SNMP_MSGKEY_RECV 			4321          /*snmpd recv queue*/
#define SNMP_MSGKEY_SEND    		5555        /*business recv queue*/
#define APP_ACK_MSGKEY 				6666   /*business ack queue*/
#define PARAM_SIZE    		128


/*ʱ��Դ״̬:gsp��ptp*/
typedef struct {
	char cddGPSClkState[PARAM_SIZE];
	char cddvigorSource[PARAM_SIZE];
} Trap_cddClkSourceState_T;

/*gpsʱ������״̬*/
typedef struct {
	char cddGPSLockState[PARAM_SIZE];
	char cddvigorSource[PARAM_SIZE];
} Trap_cddGPSLockState_T;


/*PTPʱ������״̬*/
typedef struct {
	char cddPTPLockState[PARAM_SIZE];
	char cddvigorSource[PARAM_SIZE];
} Trap_cddPTPLockState_T;

/*FPGA ����״̬*/
typedef struct {
	char cddFPGAWorkState[PARAM_SIZE];
	char cddvigorSource[PARAM_SIZE];
} Trap_cddFPGAWorkState_T;


/*������������*/
typedef struct {
	char cddNetLinkState[PARAM_SIZE];
	char cddvigorSource[PARAM_SIZE];
} Trap_cddNetLinkState_T;


/*  OMAP ����״̬*/
typedef struct {
	char cddOmapRunState[PARAM_SIZE];
	char cddvigorSource[PARAM_SIZE];
} Trap_cddOmapRunState_T;



typedef struct
{
    //int btsAlarmStatus;
    char btsAlarmType[PARAM_SIZE];
    char vigorSource[PARAM_SIZE];
}Trap_btsEquipment_T;

typedef struct
{
    char btsLinkState[PARAM_SIZE];
    char vigorSource[PARAM_SIZE];
}Trap_btsLinkState_T;

typedef struct
{
    char btsExtClock[PARAM_SIZE];
    char vigorSource[PARAM_SIZE];
}Trap_btsExtClock_T;

typedef struct
{
    char btsTxState[PARAM_SIZE];
    char btsRealTxPower[PARAM_SIZE];
    char btsVswr[PARAM_SIZE];
    char btsRssi[PARAM_SIZE];
    char btsEnvirTemperature[PARAM_SIZE];
    char btsPaTemperature[PARAM_SIZE];
    char btsDcVoltage[PARAM_SIZE];
    char btsBatVoltage[PARAM_SIZE];
    char btsFanSpeed[PARAM_SIZE];
    char vigorSource[PARAM_SIZE];
}Trap_btsState_T;

typedef struct
{
    char sccSlotNum[PARAM_SIZE];
    char sccBusy[PARAM_SIZE];
    char sccCaller[PARAM_SIZE];
    char sccCalled[PARAM_SIZE];
    unsigned char sccRtpIpAddress[PARAM_SIZE];
    char sccCallInfo[PARAM_SIZE];
    char vigorSource[PARAM_SIZE];
    char sccBSID[PARAM_SIZE];
}Trap_mscSlotState_T;

typedef struct
{
    unsigned char sccBtsIpAddress[PARAM_SIZE];
    char sccBtsState[PARAM_SIZE];
    char vigorSource[PARAM_SIZE];
}Trap_mscBtsState_T;

typedef struct
{
    char sccLinkState[PARAM_SIZE];
    char vigorSource[PARAM_SIZE];
}Trap_mscLinkState_T;

typedef struct
{
    char sccCaller[PARAM_SIZE];
    char sccCalled[PARAM_SIZE];
    char sccTalker[PARAM_SIZE];
    char vigorSource[PARAM_SIZE];
}Trap_sccPttState_T;

typedef struct
{
    char vigorSource[PARAM_SIZE];
    char equipType[PARAM_SIZE];
    unsigned char vigorDeviceState[PARAM_SIZE];
}Trap_vigorHeartbeat_T;

typedef struct
{
    char vigorSource[PARAM_SIZE];
    char equipType[PARAM_SIZE];          
    unsigned char vigorDeviceState[PARAM_SIZE];
}Trap_vigorProcAbort_T;

#define VT_3308_MIB 	FALSE        	/*ͬ����������*/
#define VT_3830_MIB   	TRUE       		/*�ŵ���*/
#define VT_3888_MIB 	FALSE        	/*ʱ�ӷ�����*/


/*trap ���������� */
#define SNMP_TRAP_QUEUE_ENTRY_LOG_ONLY      1
#define SNMP_TRAP_QUEUE_ENTRY_COMMUNITY     2
#define SNMP_TRAP_QUEUE_ENTRY_LOGGED        4
#define SNMP_TRAP_QUEUE_ENTRY_LOG_AND_TRAP  8
#define SNMP_TRAP_QUEUE_ENTRY_TRAP_ONLY     0x10
#define SNMP_TRAP_QUEUE_ENTRY_DEFAULT       SNMP_TRAP_QUEUE_ENTRY_LOG_AND_TRAP



#define SNMP_TRAP_QUEUE_FULL      1
#define SNMP_TRAP_QUEUE_ERROR     2
#define SNMP_TRAP_QUEUE_OVERLAP   4
#define SNMP_TRAP_QUEUE_OVER_WRITE      1
#define SNMP_TRAP_QUEUE_PEEK      1
#define SNMP_TRAP_MAX_COMM_STR_NAME_LEN   32
#define SNMP_TRAP_MAX_QUE_BUF_SIZE        (1024*128)
#define SNMP_TRAP_MAX_QUE_DATA_CNT        10
#define SNMP_TRAP_QUEUE_ENTRY_HDR_SIZE    ((size_t)(int)&((SNMP_TRAP_QUEUE_ENTRY_T *)0)->content)
#ifndef BOOL
#define BOOL  short
#endif

/*�����붨��*/
#define MSG_OK                 0
#define MSG_GENERROR           -1
#define MSG_TIMEOUT            -2
#define MSG_WRONGOPERCODE      -3
#define MSG_APPOPERERROR       -4

/*�����붨��*/
#define NET_IPADDR       0x0001        /*IP��ַ*/
#define NET_MASK         0x0002        /*��������*/
#define NET_GATEWAY      0x0003        /*����*/
#define NET_MAC          0x0004        /*����MAC��ַ*/
#define NET_DB_IP        0x0005        /*���ݿ�IP��ַ*/
#define NET_SC_IP        0x0006        /*ͬ������IP��ַ��ֻ����ŵ�����Ч*/
#define NET_LDS_IP       0x0007        /*���ȷ�����IP��ַ��ֻ��ͬ��������Ч*/
#define NET_RQC_IP       0x0008        /*¼��������IP��ַ��ֻ��ͬ��������Ч*/
#define NET_MGW_IP       0x0009        /*ý������IP��ַ��ֻ��ͬ��������Ч*/
#define BTS_TX_FREQ      0x0010        /*�ŵ�����Ƶ��*/
#define BTS_RX_FREQ      0x0011        /*�ŵ�����Ƶ��*/
#define BTS_TX_POWER     0x0012        /*�ŵ����书��*/
#define BTS_SQUELCH      0x0013        /*����ȼ�*/
#define BTS_CH_MODE      0x0014        /*�ŵ�����ģʽ*/
#define BTS_CH_BAND      0x0015        /*�ŵ�����*/
#define BTS_TIME_DELAY   0x0016        /*�����ӳ�ʱ��*/
#define BTS_PORT_S1      0x0017        /*ʱ϶1�˿ں�*/
#define BTS_PORT_S2      0x0018        /*ʱ϶2�˿ں�*/
#define BTS_MODEL        0x0020        /*�ŵ����ͺ�*/
#define BTS_ESN          0x0021        /*�ŵ������Ӵ���*/
#define BTS_HW_VER       0x0022        /*�ŵ���Ӳ���汾*/
#define BTS_FW_VER       0x0023        /*�ŵ�������汾*/
#define BTS_VSWR         0x0024        /*�����ѹפ����*/
#define BTS_RSSI         0x0025        /*���ճ�ǿ*/
#define BTS_ENV_TEMP     0x0026        /*�����¶�*/
#define BTS_PA_TEMP      0x0027        /*�����¶�*/
#define BTS_DC_VOLT      0x0028        /*ֱ����ѹ*/
#define BTS_BAT_VOLT     0x0029        /*��ص�ѹ*/
#define BTS_FAN_RPM      0x002A        /*����ת��*/
#define BTS_REAL_TX_POWER  0x002B      /*ʵ�ʷ��书��(��)*/
#define BTS_FAULT_MODE   0x002C        /*��������ʱ����ģʽ*/
#define BTS_SQUELCH_MODE 0x0050        /*Carrier��CTCSS/CDCSS(ģ�ⳣ��/ͬ��ģʽ��Ч)*/
#define BTS_RX_CSS       0x0051        /*������������(ģ�ⳣ��ģ/ͬ��ʽ��Ч)*/
#define BTS_TX_CSS       0x0052        /*������������(ģ�ⳣ��ģ/ͬ��ʽ��Ч)*/
#define BTS_CC           0x0053        /*ɫ��(���ֳ���/ͬ��ģʽ��Ч)*/
#define BTS_DEV_ENABLE   0x0054        /*�ŵ�������/ͣ��, enable or disable*/
#define SCC_RSSI_THRS    0x0030        /*��ѡ����*/
#define SCC_BUF_LEN      0x0031        /*����ʱ��*/
#define VIGOR_EQU_TYPE   0x0032        /*�豸����*/
#define SCC_PSTN_IP      0x0033         /*��������ip*/
#define SCC_VERSION      0x0034        /*ͬ����������汾*/
#define VIGOR_EQU_STATE  0x0035        /*�豸״̬*/
#define VIGOR_SOURCE     0x0036        /*��ϢԴ(ip+port)*/
#define ALARM_STATE      0x0040        /*������Ϣ*/
#define LINK_STATE       0x0041        /*��·״̬*/
#define EXTCLK_STATE     0x0042        /*�ⲿʱ��״̬*/
#define BTS_TX_STATE     0x0043        /*�ŵ�������״̬*/
#define SCC_SLOT_CONVERSATION_STATE 0x0044 /*����ʱ϶ͨ��״̬*/
#define SCC_PTT_STATE  0x0045          /*���Ľ�������Ϣ*/
#define PROC_ABORT_STATE  0x0046       /*Ӧ�ó����˳�*/


//####################################ʱ�ӷ���������###########################################
#define     MSG_CODE_CDD_WORK_MODE 		0x60 /*����ģʽ*/
#define     MSG_CODE_CDD_APP_VER 		0x61 /*Ӧ�ð汾*/
#define     MSG_CODE_CDD_FPGA_VER  		0x62/*fpga�汾��*/
#define     MSG_CODE_CDD_HW_VER  		0x63/*Ӳ���汾*/
#define     MSG_CODE_CDD_MODEL_STATE  	0x64/*ʱ�ӷ������ͺ�*/
#define     MSG_CODE_CDD_GPS_TIME  		0x65/*GPSsʱ��*/
#define     MSG_CODE_CDD_PTP_TIME  		0x66/*GPSsʱ��*/

//#define	CLK_DISTRIBUTE_IP			0x64
/***************************ʱ�ӷ�����TRAP��Ϣ��************************************************/
#define     SNMP_TRAP_QUEUE_CDD_CLK_SOURCE_TRAP 		0x70 /*ʱ��Դ״̬*/
#define     SNMP_TRAP_QUEUE_CDD_GPS_LOCK_TRAP 			0x71 /*GPS����״̬*/
#define     SNMP_TRAP_QUEUE_CDD_PTP_LOCK_TRAP 			0x72 /*PTPԴ����״̬*/
#define     SNMP_TRAP_QUEUE_CDD_FPGA_WORK_TRAP 			0x73 /*FPGA����״̬*/
#define     SNMP_TRAP_QUEUE_CDD_NET_LINK_TRAP 			0x74 /*��������״̬*/
#define     SNMP_TRAP_QUEUE_CDD_OMAP_RUN_TRAP 			0x75 /*OMAP����״̬*/






#define SNMP_TRAP_QUEUE_BTSALARMSTATE     ALARM_STATE
#define SNMP_TRAP_QUEUE_BTSLINKSTATE      LINK_STATE
#define SNMP_TRAP_QUEUE_BTSEXTCLOCK       EXTCLK_STATE
#define SNMP_TRAP_QUEUE_BTSTXSTATE        BTS_TX_STATE
#define SNMP_TRAP_QUEUE_SCCSLOTSTATE      SCC_SLOT_CONVERSATION_STATE
#define SNMP_TRAP_QUEUE_SCCBTSSTATE 
#define SNMP_TRAP_QUEUE_SCCLINKSTATE      LINK_STATE
#define SNMP_TRAP_QUEUE_SCCPTTSTATETRAP   SCC_PTT_STATE
#define SNMP_TRAP_QUEUE_VIGORPROCABORT    PROC_ABORT_STATE
#define SNMP_TRAP_QUEUE_VIGORHEARTBEAT    0

#if 0
typedef  enum
{
    SNMP_TRAP_QUEUE_COLDSTART = 0,
    SNMP_TRAP_QUEUE_WARMSTART,
    SNMP_TRAP_QUEUE_LINKDOWN,
    SNMP_TRAP_QUEUE_LINKUP,
    SNMP_TRAP_QUEUE_AUTHFAIL,
    SNMP_TRAP_QUEUE_EGPNEIGHBORLOSS,
    SNMP_TRAP_QUEUE_ENTERPRISESPECIFIC,
    SNMP_TRAP_QUEUE_XDJ_EQUIPMENT,
    SNMP_TRAP_QUEUE_XDJ_LINKSTATE,
    SNMP_TRAP_QUEUE_XDJ_EXTCLOCK,
    SNMP_TRAP_QUEUE_BTSTXSTATE,
    SNMP_TRAP_QUEUE_SCCSLOTSTATE,
    SNMP_TRAP_QUEUE_SCCBTSSTATE,
    SNMP_TRAP_QUEUE_SCCLINKSTATE,
    SNMP_TRAP_QUEUE_SCCPTTSTATETRAP,
    SNMP_TRAP_QUEUE_VIGORHEARTBEAT,
    SNMP_TRAP_QUEUE_VIGORPROCABORT,
}SNMP_TRAP_TrapType_E;
#endif

typedef  enum
{
    TRAP_EVENT_SEND_TRAP_OPTION_DEFAULT = 0,
    TRAP_EVENT_SEND_TRAP_OPTION_LOG_AND_TRAP,
    TRAP_EVENT_SEND_TRAP_OPTION_LOG_ONLY,
    TRAP_EVENT_SEND_TRAP_OPTION_TRAP_ONLY,
}TRAP_EVENT_SendTrapOption_E;

union semun 
{
    int     val;            /* value for SETVAL */
    struct  semid_ds *buf;  /* buffer for IPC_STAT & IPC_SET */
    u_short *array;         /* array for GETALL & SETALL */
};

/*��Ϣ���ݶ���*/
typedef struct 
{
    unsigned long   oper_code;        /*������*/
    int             error_code;       /*������, 0 is ok, -1 is error*/

    /*This union contains msg data*/
    union
    {
        unsigned char             msg_data_str[MAX_SIZE];       /* �ַ������� */
        int                       msg_data_int;                 /* ��������   */
        Trap_btsEquipment_T       bts_equipment_trap;
        Trap_btsLinkState_T       bts_linkstate_trap;
        Trap_btsExtClock_T        bts_extclock_trap;
        Trap_btsState_T         bts_txstate_trap;
        Trap_mscSlotState_T       msc_slotstate_trap;
        Trap_mscBtsState_T        msc_btsstate_trap;
        Trap_mscLinkState_T       msc_linkstate_trap;
        Trap_vigorHeartbeat_T     vigor_heartbeat_trap;
        Trap_vigorProcAbort_T     vigor_procabort_trap;
		
		Trap_cddClkSourceState_T	cdd_ClkSourceState_trap;/*ʱ��Դ״̬*/
		Trap_cddGPSLockState_T		cdd_GPSLockState_trap;	/*ʱ������״̬ */
		Trap_cddPTPLockState_T		cdd_PTPLockState_trap;		/*����ʱ��*/
		Trap_cddFPGAWorkState_T 	cdd_FPGAState_trap;/*ʱ��ת��״̬*/
		Trap_cddNetLinkState_T		cdd_NetLinkState_trap;	/*��������״̬*/		
		Trap_cddOmapRunState_T		cdd_OmapRunState_trap;	/*������״̬*/


    }u_data;
}SNMP_MSG_T;

/*��Ϣ���Ͷ���*/
#define CMD_GET  0x1000     /* ��ȡ���� (SNMP -> APP) */
#define CMD_SET  0x2000     /* �������� (SNMP -> APP) */
#define CMD_ACK  0x8000     /* Ӧ������ (SNMP <- APP) */
#define CMD_TRAP 0xA000     /* �澯��Ϣ (SNMP <- APP) */

/*��Ϣ����*/
typedef struct
{
    long msg_type;                       /*��Ϣ���� ��get/set/ack/trap*/
    SNMP_MSG_T snmp_msg;
}QUEUE_MSG_T;

typedef struct TRAP_EVENT_TrapQueueData_S
{
    struct TRAP_EVENT_TrapData_S *next;
    uint32_t trap_time;
    uint32_t remainRetryTimes;
    uint32_t trap_type;
    BOOL     community_specified;
    TRAP_EVENT_SendTrapOption_E flag;
    uint8_t  community[SNMP_TRAP_MAX_COMM_STR_NAME_LEN + 1];
    uint8_t  data[0];
}TRAP_EVENT_TrapQueueData_T;

typedef struct TRAP_EVENT_TrapData_S
{
    struct TRAP_EVENT_TrapData_S *next;
    uint32_t trap_time;
    uint32_t remainRetryTimes;
    uint32_t trap_type;
    BOOL     community_specified;
    TRAP_EVENT_SendTrapOption_E flag;
    uint8_t  community[SNMP_TRAP_MAX_COMM_STR_NAME_LEN + 1];

    union
    {
        Trap_btsEquipment_T       bts_equipment_trap;
        Trap_btsLinkState_T       bts_linkstate_trap;
        Trap_btsExtClock_T        bts_extclock_trap;
        Trap_btsState_T             bts_txstate_trap;
        Trap_mscSlotState_T       msc_slotstate_trap;
        Trap_mscBtsState_T        msc_btsstate_trap;
        Trap_mscLinkState_T       msc_linkstate_trap;
        Trap_sccPttState_T        scc_PttState_Trap;
        Trap_vigorHeartbeat_T     vigor_heartbeat_trap;
        Trap_vigorProcAbort_T     vigor_procabort_trap;
		
		Trap_cddClkSourceState_T	cdd_ClkSourceState_trap;/*ʱ��Դ״̬*/
		Trap_cddGPSLockState_T		cdd_GPSLockState_trap;	/*ʱ������״̬ */
		Trap_cddPTPLockState_T		cdd_PTPLockState_trap;		/*����ʱ��*/
		Trap_cddFPGAWorkState_T 	cdd_FPGAState_trap;/*ʱ��ת��״̬*/
		Trap_cddNetLinkState_T		cdd_NetLinkState_trap;	/*��������״̬*/		
		Trap_cddOmapRunState_T		cdd_OmapRunState_trap;	/*������״̬*/

		
    }u;
}TRAP_EVENT_TrapData_T;

typedef struct SNMP_TRAP_QUEUE_ENTRY
{
    uint16_t    size;
    uint16_t    type;
    uint32_t    time;
    uint8_t     retries;
    uint8_t     flags;
    union
    {
        struct
        {
            uint8_t len;
            uint8_t data[1];
        }comm;
        uint8_t  data[1];
    }content;
}SNMP_TRAP_QUEUE_ENTRY_T;

typedef struct SNMP_TRAP_Queue_BUF_S
{
    uint32_t                magic;
    uint32_t                size;
    volatile  uint32_t      max_entries;
    volatile  uint32_t      max_size;
    volatile  uint32_t      entries;
    volatile  uint16_t      flags;
    volatile  uint16_t      errcnt;
    volatile  uint32_t      wr_off;
    volatile  uint32_t      rd_off;
    volatile  uint32_t      mtime;
}SNMP_TRAP_Queue_BUF_T;


typedef struct
{
    uint32_t                sem;
    SNMP_TRAP_Queue_BUF_T   *buf;
}SNMP_TRAP_Queue_T;

//pthread_mutex_t mut;
//pthread_mutex_t mut_trap;

void init_vigorMsgQueue(void);
int process_snmpMsg(QUEUE_MSG_T *p_msg);
void SNMP_TRAP_SendHeartBeatTrap(int signo);

#endif
