namespace TacacsSharp
{
    public enum PacketType
    {
        TAC_PLUS_AUTHEN = 0x01,
        TAC_PLUS_AUTHOR = 0x02,
        TAC_PLUS_ACCT = 0x03
    }

    public enum EncryptionFlag
    {
        TAC_PLUS_ENCRYPTED_FLAG = 0x0,
        TAC_PLUS_UNENCRYPTED_FLAG = 0x1,
    }

    public enum CommunicationFlag
    {
        CONTINUES = 0x0,
        ENDED = 0x1
    }

    public enum AuthenticationStatus
    {
        PASS = 0x01,
        FAIL = 0x02,
        GETDATA = 0x03,
        GETUSER = 0x04,
        GETPASS = 0x05,
        RESTART = 0x06,
        ERROR = 0x07,
        FOLLOW = 0x21
    }

    public enum PrivilegeLevel
    {
        TAC_PLUS_PRIV_LVL_MAX = 0x0f,
        TAC_PLUS_PRIV_LVL_ROOT = 0x0f,
        TAC_PLUS_PRIV_LVL_USER = 0x01,
        TAC_PLUS_PRIV_LVL_MIN = 0x00,
    }

    public enum AuthenticationType
    {
        TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01,
        TAC_PLUS_AUTHEN_TYPE_PAP = 0x02,
        TAC_PLUS_AUTHEN_TYPE_CHAP = 0x03,
        TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x05,
        TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 = 0x06,
    }

    public enum AuthenticationService
    {
        TAC_PLUS_AUTHEN_SVC_NONE = 0x00,
        TAC_PLUS_AUTHEN_SVC_LOGIN = 0x01,
        TAC_PLUS_AUTHEN_SVC_ENABLE = 0x02,
        TAC_PLUS_AUTHEN_SVC_PPP = 0x03,
        TAC_PLUS_AUTHEN_SVC_ARAP = 0x04,
        TAC_PLUS_AUTHEN_SVC_PT = 0x05,
        TAC_PLUS_AUTHEN_SVC_RCMD = 0x06,
        TAC_PLUS_AUTHEN_SVC_X25 = 0x07,
        TAC_PLUS_AUTHEN_SVC_NASI = 0x08,
        TAC_PLUS_AUTHEN_SVC_FWPROXY = 0x09,
    }

    public enum AuthenticationMethod
    {
        TAC_PLUS_AUTHEN_METH_NOT_SET = 0x00,
        TAC_PLUS_AUTHEN_METH_NONE = 0x01,
        TAC_PLUS_AUTHEN_METH_KRB5 = 0x02,
        TAC_PLUS_AUTHEN_METH_LINE = 0x03,
        TAC_PLUS_AUTHEN_METH_ENABLE = 0x04,
        TAC_PLUS_AUTHEN_METH_LOCAL = 0x05,
        TAC_PLUS_AUTHEN_METH_TACACSPLUS = 0x06,
        TAC_PLUS_AUTHEN_METH_GUEST = 0x08,
        TAC_PLUS_AUTHEN_METH_RADIUS = 0x10,
        TAC_PLUS_AUTHEN_METH_KRB4 = 0x11,
        TAC_PLUS_AUTHEN_METH_RCMD = 0x20
    }

    public enum AuthorizationStatus
    {
        TAC_PLUS_AUTHOR_STATUS_PASS_ADD = 0x01,
        TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02,
        TAC_PLUS_AUTHOR_STATUS_FAIL = 0x10,
        TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11,
        TAC_PLUS_AUTHOR_STATUS_FOLLOW = 0x21
    }

    public enum AccountingFlag
    {
        TAC_PLUS_ACCT_FLAG_START = 0x02,
        TAC_PLUS_ACCT_FLAG_STOP = 0x04,
        TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x08,
    }

    public enum AccountingStatus
    {
        TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01,
        TAC_PLUS_ACCT_STATUS_ERROR = 0x02,
        TAC_PLUS_ACCT_STATUS_FOLLOW = 0x21,
    }
}