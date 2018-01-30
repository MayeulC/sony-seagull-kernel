/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright (C) 2012 Sony Mobile Communications AB.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_WAPIINFOERROR_H_
#define __WLAN_WAPI_WAPIINFOERROR_H_

/*========================================================
WLAN_WAPI_WAPIINFOERROR.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


=========================================================*/

/*========================================================

		EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

=========================================================*/

typedef struct  _ERRORINFORMATION
{
	int    errorID;
	char   errorInformation[256];
}ERRORINFORMATION;

typedef struct  _INDICATEINFORMATION
{
	int    notifyID;
	char   notifyInformation[256];
}INDICATEINFORMATION;


#define      notifyWaitingAuthActive            1
#define      notifyReceiveAuthActive            2
#define      notifySendAccessAuthRequ           3
#define      notifyReSendAccessAuthRequ         4
#define      notifyWaitingAccessAuthResp        5
#define      notifyReceiveAccessAuthResp        6
#define      notifyWaitingSessNegRequ           7
#define      notifyReceiveSessNegRequ           8
#define      notifySendSessNegResp              9
#define      notifyReSendSessNegResp            10
#define      notifyWaitingSessNegAck            11
#define      notifyReceiveSessNegAck            12
#define      notifyWaitingGroupKeyNotify        13
#define      notifyReceiveGroupKeyNotify        14
#define      notifySendGroupKeyResp             15

#define      notifySendSessNegRequ              16
#define      notifyWaitingSessNegResp           17
#define      notifyReSendSessNegRequ            18
#define      notifyReceiveSessNegResp           19
#define      notifySendSessNegAck               20
#define      notifySendGroupKeyRequ             21
#define      notifyReSendSessNegAck             22
#define      notifyWaitingGroupKeyResp          23
#define      notifyReSendGroupKeyNotify         24
#define      notifyReceiveGroupKeyResp          25
#define      notifyWaitingGroupNotifyResp       26

#define      notifyDisAssociate                 31
#define      notifyOpenAdapterPort              32
#define      notifyCloseAdapterPort             33
#define      notifySetWAPIKey                   34
#define      notifySetAccessAPConfigParam       35

#define      notifyCreateIBSS                   36
#define      notifySetIBSSConfigParam           37

#define      notifyEncryptFinished              38
#define      notifyRefreshKey                   39
#define      Associating                        70
#define      Authenticating                     71
#define      Authenticated                      72
#define      FaildAuthenticated                 73
#define      DisAuthenticated                   74


#define      wapi_err_TimeOutWaitAccessAuthResp      101
#define      wapi_err_TimeOutWaitSessNegAck          102

#define      wapi_err_STAaeIdentityMisMatch          103
#define      wapi_err_STAasueIdentityMisMatch        104
#define      wapi_err_FLAGRefreshBKMisMatch          105
#define      wapi_err_FLAGPreAuthMisMatch            106
#define      wapi_err_ASUEChallengeMisMatch          107
#define      wapi_err_ASUEKeyDataMisMatch            108
#define      wapi_err_VerifyAESignFailure            109
#define      wapi_err_VerifyAccessResultFailure      110

#define      wapi_err_VerifyASUEASUSignFailure            111
#define      wapi_err_VerifyAECertificateAuthResult       112

#define      wapi_err_BKSAInvalidate                      113
#define      wapi_err_BKIDMisMatch                        114
#define      wapi_err_USKSAInvalidate                     115
#define      wapi_err_AEChallengeMisMatch                 116
#define      wapi_err_VerifyHMACFailure                   118

#define      wapi_err_WIEaeMisMatch                       119

#define      wapi_err_KeyNotifyIndicateNotAdd             120

#define      wapi_err_NoUseCertificate                    121

#define      wapi_err_UnPackAuthActive                    122
#define      wapi_err_UnPackAccessAuthResp                123
#define      wapi_err_UnPackSessNegRequ                   124
#define      wapi_err_UnPackSessNegAck                    125
#define      wapi_err_UnPackGroupKeyNotice                126

#define      wapi_err_SendAccessAuthRequ                    127
#define      wapi_err_VerifyASUECertificateAuthResult       128

#define      wapi_err_SendSessionNegResp                    129
#define      wapi_err_DecryptNMKFailure                     130
#define      wapi_err_SendGroupKeyResp                      131
#define      wapi_err_SendSessionNegRequ                    132
#define      wapi_err_TimeOutWaitSessNegResp                133
#define      wapi_err_UnPackSessNegResp                     134
#define      wapi_err_UnSupportSingleKeyCode                135
#define      wapi_err_SendSessionNegAck                     136
#define      wapi_err_EncryptNMKFailure                     137
#define      wapi_err_TimeOutGroupKeyResp                   138
#define      wapi_err_SendGroupKeyNotify                    139
#define      wapi_err_UnPackGroupKeyResp                    140
#define      wapi_err_GroupKeyRespMSKIDMisMatch             141
#define      wapi_err_GroupKeyRespUSKIDMisMatch             142
#define      wapi_err_GroupKeyRespADDIDMisMatch             143
#define      wapi_err_GroupKeyRespKeyNotifyIDMisMatch       144
#define      wapi_err_NoSetupCertificate                    145
#define      wapi_err_SearchCertificateIdentity             146
#define      wapi_err_NoUseASCertificate                    147
#define      wapi_err_SearchCertificateIssureName           148
#define      wapi_err_EnumSystemCertificate                 149
#define      wapi_err_ProcessStatues                               150
#define      wapi_err_ProcessStatues_auth_notok_and_wai_not_begin  151
#define      wapi_err_ProcessStatues_wai_not_begin                 152
#define      wapi_err_ProcessStatues_not_support                   153
#define      wapi_err_AUTH_PROTOCOL_FAIL                           154
#define      wapi_err_ProcessStatues_KEY_NEGING                    155
#define      wapi_err_ProcessStatues_KEY_NEGING_and_wai_not_begin  156

#define    wapi_Unicast_Key_installation_Failed                    157
#define    wapi_Pack_Group_Key_Resp_Failed                         158
#define  wapi_Pack_Group_Key_Hmac_mismatch                         159



#define      wapi_err_CreateLogFile                          200
#define      wapi_err_StartDriver                            201
#define      wapi_err_GetValidWLANAdapterInfo                202
#define      wapi_err_OpenValidWLANAdapterInfo               203
#define      wapi_err_CloseProtocolDevice                    204
#define      wapi_err_StopDriver                             205
#define      wapi_err_IndicateProcPointNULL                  206
#define      wapi_err_CreateQuitAccessAssociateAPEvent       207
#define      wapi_err_CreateQuitCreateAdhocEvent             208
#define      wapi_err_DisAssociate                           209
#define      wapi_err_InvalidAdapterInfo                     210
#define      wapi_err_Query80211BSSIDList                    211
#define      wapi_err_LoadGBWCertificateFailure              212
#define      wapi_err_LoadX509UserCertificateFailure         213
#define      wapi_err_LoadX509ASCertificateFailure           214
#define      wapi_err_GetDLLVersionFailure                   215
#define      wapi_err_GetFileVersionInfoFailure              216
#define      wapi_err_GetFileLastWriteTimeFailure            217
#define      wapi_err_CreateAccessAPThreadFailure            218
#define      wapi_err_PreShareKeyIsNULL                      219
#define      wapi_err_CreateAdhocFailure                     220
#define      wapi_err_CreateAdhocThreadFailure               221
#define      wapi_err_GetCertificateSubjectName              222
#define      wapi_err_GetCertificateIssureName               223
#define      wapi_err_GetCertificateSerialNumber             224
#define      wapi_err_GetCertificatePov                      225


#define      wapi_err_RegCertificateSystemStore              226
#define      wapi_err_EnumCertificateFailure                 227
#define      wapi_err_NoSetupValidAdapter                    228
#define      wapi_err_DeleteCertificateFailure               229



#define      wapi_err_StopWZCDriver                          230

#define      wapi_err_AllocMemFaild                          231
#define      wapi_err_FreeMemFaild                           232

#define      wapi_err_KeystoreError                          233

#define       wapi_err_OtherFaild			     250



#endif	/*__WLAN_WAPI_WAPIINFOERROR_H_*/
