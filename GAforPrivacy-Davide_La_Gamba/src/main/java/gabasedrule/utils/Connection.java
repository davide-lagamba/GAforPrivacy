package gabasedrule.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Connection {
    public static final int COLUMN_DURATION = 0;
    public static final int COLUMN_PROTOCOL_TYPE = 1;
    public static final int COLUMN_SERVICE = 2;
    public static final int COLUMN_FLAG = 3;
    public static final int COLUMN_SRC_BYTES = 4;
    public static final int COLUMN_DST_BYTES = 5;
    public static final int COLUMN_LAND = 6;
    public static final int COLUMN_WRONG_FRAGMENT = 7;
    public static final int COLUMN_URGENT = 8;
    public static final int COLUMN_HOT = 9;// non nelle prime 18 feature
    public static final int COLUMN_NUM_FAILED_LOGINS = 10;// non nelle prime 18 feature
    public static final int COLUMN_LOGGED_IN = 11;// non nelle prime 18 feature
    public static final int COLUMN_NUM_COMPROMISED = 12;// non nelle prime 18 feature
    public static final int COLUMN_ROOT_SHELL = 13;// non nelle prime 18 feature
    public static final int COLUMN_SU_ATTEMPTED = 14;// non nelle prime 18 feature
    public static final int COLUMN_NUM_ROOT = 15;// non nelle prime 18 feature
    public static final int COLUMN_NUM_FILES_CREATIONS = 16;// non nelle prime 18 feature
    public static final int COLUMN_NUM_SHELLS = 17;// non nelle prime 18 feature
    public static final int COLUMN_NUM_ACCESS_FILES = 18;// non nelle prime 18 feature
    public static final int COLUMN_NUM_OUTBOUND_CMDS = 19;// non nelle prime 18 feature
    public static final int COLUMN_IS_HOST_LOGIN = 20;// non nelle prime 18 feature
    public static final int COLUMN_IS_GUEST_LOGIN = 21;// non nelle prime 18 feature
    public static final int COLUMN_COUNT = 22;
    public static final int COLUMN_SRV_COUNT = 23;
    public static final int COLUMN_SERROR_RATE = 24;
    public static final int COLUMN_SRV_SERROR_RATE = 25;
    public static final int COLUMN_RERROR_RATE = 26;
    public static final int COLUMN_SRV_RERROR_RATE = 27;
    public static final int COLUMN_SAME_SRV_RATE = 28;
    public static final int COLUMN_DIFF_SRV_RATE = 29;
    public static final int COLUMN_SRV_DIFF_HOST_RATE = 30;
    public static final int COLUMN_DST_HOST_COUNT = 31;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOST_SRV_COUNT = 32;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOST_SAME_SRV_RATE = 33;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOST_DIFF_SRV_RATE = 34;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOME_SAME_SRC_PORT_RATE = 35;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOST_SRV_DIFF_HOST_RATE = 36;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOST_SERROR_RATE = 37;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOST_SRV_SERROR_RATE = 38;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOST_RERROR_RATE = 39;// non nelle prime 18 feature
    public static final int COLUMN_DST_HOST_SRV_RERROR_RATE = 40;// non nelle prime 18 feature
    public static final int COLUMN_LABEL=41;

    public static final Map<String, Integer> protocolTypeMap=new HashMap<String, Integer>() {{
        put("tcp", 1);
        put("udp", 2);
        put("icmp", 3);}};
    public static final Map<String, Integer> serviceMap=new HashMap<String, Integer>() {{
        put("http", 1);
        put("smtp", 2);
        put("finger", 3);
        put("domain_u", 4);
        put("auth", 5);
        put("telnet", 6);
        put("ftp", 7);
        put("eco_i", 8);
        put("ntp_u", 9);
        put("ecr_i", 10);
        put("other", 11);
        put("private", 12);
        put("pop_3", 13);
        put("ftp_data", 14);
        put("rje", 15);
        put("time", 16);
        put("mtp", 17);
        put("link", 18);
        put("remote_job", 19);
        put("gopher", 20);
        put("ssh", 21);
        put("name", 22);
        put("whois", 23);
        put("domain", 24);
        put("login", 25);
        put("imap4", 26);
        put("daytime", 27);
        put("ctf", 28);
        put("nntp", 29);
        put("shell", 30);
        put("IRC", 31);
        put("nnsp", 32);
        put("http_443", 33);
        put("exec", 34);
        put("printer", 35);
        put("efs", 36);
        put("courier", 37);
        put("uucp", 38);
        put("klogin", 39);
        put("kshell", 40);
        put("echo", 41);
        put("discard", 42);
        put("systat", 43);
        put("supdup", 44);
        put("iso_tsap", 45);
        put("hostnames", 46);
        put("csnet_ns", 47);
        put("pop_2", 48);
        put("sunrpc", 49);
        put("uucp_path", 50);
        put("netbios_ns", 51);
        put("netbios_ssn", 52);
        put("netbios_dgm", 53);
        put("sql_net", 54);
        put("vmnet", 55);
        put("bgp", 56);
        put("Z39_50", 57);
        put("ldap", 58);
        put("netstat", 59);
        put("urh_i", 60);
        put("X11", 61);
        put("urp_i", 62);
        put("pm_dump", 63);
        put("tftp_u", 64);
        put("tim_i", 65);
        put("red_i", 66);}};
    public static final Map<String, Integer> flagMap=new HashMap<String, Integer>() {{
        put("SF", 1);
        put("S1", 2);
        put("REJ", 3);
        put("S2", 4);
        put("S0", 5);
        put("S3", 6);
        put("RSTO", 7);
        put("RSTR", 8);
        put("RSTOS0", 9);
        put("OTH", 10);
        put("SH", 11);
    }};
    private Integer duration; //Durata della connessione  (0, 58329)
    private Integer protocolType; //Protocollo di connessione (e.g. tcg, udp) [1, 3]
    private Integer service; //Servizio della destinazione (e.g. telnet, ftp) [1, 66]
    private Integer flag; //Status flag della connessione [1, 11]
    private Integer srcBytes; //Bytes inviati dalla fonte alla destinazione (0, 999)
    private Integer dstBytes; //Bytes inviati dalla destinazione alla fonte (0, 9999)
    private Integer land; //1 se la connessione è da/a lo stesso host o porta, 0 altrimenti [0, 1]
    private Integer wrongFragment; //numero di frammenti errati (0, 3)
    private Integer urgent; //numero di pacchetti urgenti (0, 3)
    private Integer count; //numero di connessioni allo stesso host dalla stessa connessione negli ultimi 2 secondi (0, 99)
    private Integer srvCount; //numero di connessioni allo stesso servizio dalla stessa connessione negli ultimi 2 secondi (0, 99)
    private Integer serrorRate; //% di connessioni che hanno "SYN" error (0.00, 1.00)
    private Integer srvSerrorRate; //% di connessioni che hanno "SYN" error (0.00, 1.00)
    private Integer rerrorRate; //% di connessioni che hanno "REJ" error (0.00, 1.00)
    private Integer srvRerrorRate; //% di connessioni che hanno "REJ" error (0.00, 1.00)
    private Integer sameSrvRate; //% di connessioni allo stesso servizio (0.00, 1.00)
    private Integer diffSrvRate; //% di connessioni a differenti servizi (0.00, 1.00)
    private Integer srvDiffHostRate; //% di connessioni a diversi host (0.00, 1.00)
    private String label; //normal o tipo di attacco

    private Integer hot; //(0, 30)
    private Integer numFailedLogins; //(0, 5)
    private Integer loggedIn;//(0, 1)
    private Integer numCompromised;//(0, 884)
    private Integer rootShell;//(0, 1)
    private Integer suAttempted;//(0, 2)
    private Integer numRoot;//(0, 993)
    private Integer numFilesCreations;//(0, 28)
    private Integer numShells;//(0, 2)
    private Integer numAccessFiles;//(0, 8)
    private Integer numOutboundCmds;//(0, 0)
    private Integer isHostLogin;//(0, 1)
    private Integer isGuestLogin;//(0, 1)
    private Integer dstHostCount;//(0, 260)
    private Integer dstHostSrvCount;//(0, 260)
    private Integer dstHostSameSrvRate;//(0.00, 1.00)
    private Integer dstHostDiffSrvRate;//(0.00, 1.00)
    private Integer dstHomeSameSrcPortRate;//(0.00, 1.00)
    private Integer dstHostSrvDiffHostRate;//(0.00, 1.00)
    private Integer dstHostSerrorRate;//(0.00, 1.00)
    private Integer dstHostSrvSerrorRate;//(0.00, 1.00)
    private Integer dstHostRerrorRate;//(0.00, 1.00)
    private Integer dstHostSrvRerrorRate;//(0.00, 1.00)

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Connection that = (Connection) o;
        return Objects.equals(getDuration(), that.getDuration()) && Objects.equals(getProtocolType(), that.getProtocolType()) && Objects.equals(getService(), that.getService()) && Objects.equals(getFlag(), that.getFlag()) && Objects.equals(getSrcBytes(), that.getSrcBytes()) && Objects.equals(getDstBytes(), that.getDstBytes()) && Objects.equals(getLand(), that.getLand()) && Objects.equals(getWrongFragment(), that.getWrongFragment()) && Objects.equals(getUrgent(), that.getUrgent()) && Objects.equals(getCount(), that.getCount()) && Objects.equals(getSrvCount(), that.getSrvCount()) && Objects.equals(getSerrorRate(), that.getSerrorRate()) && Objects.equals(getSrvSerrorRate(), that.getSrvSerrorRate()) && Objects.equals(getRerrorRate(), that.getRerrorRate()) && Objects.equals(getSrvRerrorRate(), that.getSrvRerrorRate()) && Objects.equals(getSameSrvRate(), that.getSameSrvRate()) && Objects.equals(getDiffSrvRate(), that.getDiffSrvRate()) && Objects.equals(getSrvDiffHostRate(), that.getSrvDiffHostRate()) && Objects.equals(getLabel(), that.getLabel()) && Objects.equals(getHot(), that.getHot()) && Objects.equals(getNumFailedLogins(), that.getNumFailedLogins()) && Objects.equals(getLoggedIn(), that.getLoggedIn()) && Objects.equals(getNumCompromised(), that.getNumCompromised()) && Objects.equals(getRootShell(), that.getRootShell()) && Objects.equals(getSuAttempted(), that.getSuAttempted()) && Objects.equals(getNumRoot(), that.getNumRoot()) && Objects.equals(getNumFilesCreations(), that.getNumFilesCreations()) && Objects.equals(getNumShells(), that.getNumShells()) && Objects.equals(getNumAccessFiles(), that.getNumAccessFiles()) && Objects.equals(getNumOutboundCmds(), that.getNumOutboundCmds()) && Objects.equals(getIsHostLogin(), that.getIsHostLogin()) && Objects.equals(getIsGuestLogin(), that.getIsGuestLogin()) && Objects.equals(getDstHostCount(), that.getDstHostCount()) && Objects.equals(getDstHostSrvCount(), that.getDstHostSrvCount()) && Objects.equals(getDstHostSameSrvRate(), that.getDstHostSameSrvRate()) && Objects.equals(getDstHostDiffSrvRate(), that.getDstHostDiffSrvRate()) && Objects.equals(getDstHomeSameSrcPortRate(), that.getDstHomeSameSrcPortRate()) && Objects.equals(getDstHostSrvDiffHostRate(), that.getDstHostSrvDiffHostRate()) && Objects.equals(getDstHostSerrorRate(), that.getDstHostSerrorRate()) && Objects.equals(getDstHostSrvSerrorRate(), that.getDstHostSrvSerrorRate()) && Objects.equals(getDstHostRerrorRate(), that.getDstHostRerrorRate()) && Objects.equals(getDstHostSrvRerrorRate(), that.getDstHostSrvRerrorRate());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getDuration(), getProtocolType(), getService(), getFlag(), getSrcBytes(), getDstBytes(), getLand(), getWrongFragment(), getUrgent(), getCount(), getSrvCount(), getSerrorRate(), getSrvSerrorRate(), getRerrorRate(), getSrvRerrorRate(), getSameSrvRate(), getDiffSrvRate(), getSrvDiffHostRate(), getLabel(), getHot(), getNumFailedLogins(), getLoggedIn(), getNumCompromised(), getRootShell(), getSuAttempted(), getNumRoot(), getNumFilesCreations(), getNumShells(), getNumAccessFiles(), getNumOutboundCmds(), getIsHostLogin(), getIsGuestLogin(), getDstHostCount(), getDstHostSrvCount(), getDstHostSameSrvRate(), getDstHostDiffSrvRate(), getDstHomeSameSrcPortRate(), getDstHostSrvDiffHostRate(), getDstHostSerrorRate(), getDstHostSrvSerrorRate(), getDstHostRerrorRate(), getDstHostSrvRerrorRate());
    }

    @Override
    public String toString() {
        return "Connection{" +
                "duration=" + duration +
                ", protocolType=" + protocolType +
                ", service=" + service +
                ", flag=" + flag +
                ", srcBytes=" + srcBytes +
                ", dstBytes=" + dstBytes +
                ", land=" + land +
                ", wrongFragment=" + wrongFragment +
                ", urgent=" + urgent +
                ", count=" + count +
                ", srvCount=" + srvCount +
                ", serrorRate=" + serrorRate +
                ", srvSerrorRate=" + srvSerrorRate +
                ", rerrorRate=" + rerrorRate +
                ", srvRerrorRate=" + srvRerrorRate +
                ", sameSrvRate=" + sameSrvRate +
                ", diffSrvRate=" + diffSrvRate +
                ", srvDiffHostRate=" + srvDiffHostRate +
                ", label='" + label + '\'' +
                ", hot=" + hot +
                ", numFailedLogins=" + numFailedLogins +
                ", loggedIn=" + loggedIn +
                ", numCompromised=" + numCompromised +
                ", rootShell=" + rootShell +
                ", suAttempted=" + suAttempted +
                ", numRoot=" + numRoot +
                ", numFilesCreations=" + numFilesCreations +
                ", numShells=" + numShells +
                ", numAccessFiles=" + numAccessFiles +
                ", numOutboundCmds=" + numOutboundCmds +
                ", isHostLogin=" + isHostLogin +
                ", isGuestLogin=" + isGuestLogin +
                ", dstHostCount=" + dstHostCount +
                ", dstHostSrvCount=" + dstHostSrvCount +
                ", dstHostSameSrvRate=" + dstHostSameSrvRate +
                ", dstHostDiffSrvRate=" + dstHostDiffSrvRate +
                ", dstHomeSameSrcPortRate=" + dstHomeSameSrcPortRate +
                ", dstHostSrvDiffHostRate=" + dstHostSrvDiffHostRate +
                ", dstHostSerrorRate=" + dstHostSerrorRate +
                ", dstHostSrvSerrorRate=" + dstHostSrvSerrorRate +
                ", dstHostRerrorRate=" + dstHostRerrorRate +
                ", dstHostSrvRerrorRate=" + dstHostSrvRerrorRate +
                '}';
    }

    public Integer getHot() {
        return hot;
    }

    public void setHot(Integer hot) {
        this.hot = hot;
    }

    public Integer getNumFailedLogins() {
        return numFailedLogins;
    }

    public void setNumFailedLogins(Integer numFailedLogins) {
        this.numFailedLogins = numFailedLogins;
    }

    public Integer getLoggedIn() {
        return loggedIn;
    }

    public void setLoggedIn(Integer loggedIn) {
        this.loggedIn = loggedIn;
    }

    public Integer getNumCompromised() {
        return numCompromised;
    }

    public void setNumCompromised(Integer numCompromised) {
        this.numCompromised = numCompromised;
    }

    public Integer getRootShell() {
        return rootShell;
    }

    public void setRootShell(Integer rootShell) {
        this.rootShell = rootShell;
    }

    public Integer getSuAttempted() {
        return suAttempted;
    }

    public void setSuAttempted(Integer suAttempted) {
        this.suAttempted = suAttempted;
    }

    public Integer getNumRoot() {
        return numRoot;
    }

    public void setNumRoot(Integer numRoot) {
        this.numRoot = numRoot;
    }

    public Integer getNumFilesCreations() {
        return numFilesCreations;
    }

    public void setNumFilesCreations(Integer numFilesCreations) {
        this.numFilesCreations = numFilesCreations;
    }

    public Integer getNumShells() {
        return numShells;
    }

    public void setNumShells(Integer numShells) {
        this.numShells = numShells;
    }

    public Integer getNumAccessFiles() {
        return numAccessFiles;
    }

    public void setNumAccessFiles(Integer numAccessFiles) {
        this.numAccessFiles = numAccessFiles;
    }

    public Integer getNumOutboundCmds() {
        return numOutboundCmds;
    }

    public void setNumOutboundCmds(Integer numOutboundCmds) {
        this.numOutboundCmds = numOutboundCmds;
    }

    public Integer getIsHostLogin() {
        return isHostLogin;
    }

    public void setIsHostLogin(Integer isHostLogin) {
        this.isHostLogin = isHostLogin;
    }

    public Integer getIsGuestLogin() {
        return isGuestLogin;
    }

    public void setIsGuestLogin(Integer isGuestLogin) {
        this.isGuestLogin = isGuestLogin;
    }

    public Integer getDstHostCount() {
        return dstHostCount;
    }

    public void setDstHostCount(Integer dstHostCount) {
        this.dstHostCount = dstHostCount;
    }

    public Integer getDstHostSrvCount() {
        return dstHostSrvCount;
    }

    public void setDstHostSrvCount(Integer dstHostSrvCount) {
        this.dstHostSrvCount = dstHostSrvCount;
    }

    public Integer getDstHostSameSrvRate() {
        return dstHostSameSrvRate;
    }

    public void setDstHostSameSrvRate(Integer dstHostSameSrvRate) {
        this.dstHostSameSrvRate = dstHostSameSrvRate;
    }

    public Integer getDstHostDiffSrvRate() {
        return dstHostDiffSrvRate;
    }

    public void setDstHostDiffSrvRate(Integer dstHostDiffSrvRate) {
        this.dstHostDiffSrvRate = dstHostDiffSrvRate;
    }

    public Integer getDstHomeSameSrcPortRate() {
        return dstHomeSameSrcPortRate;
    }

    public void setDstHomeSameSrcPortRate(Integer dstHomeSameSrcPortRate) {
        this.dstHomeSameSrcPortRate = dstHomeSameSrcPortRate;
    }

    public Integer getDstHostSrvDiffHostRate() {
        return dstHostSrvDiffHostRate;
    }

    public void setDstHostSrvDiffHostRate(Integer dstHostSrvDiffHostRate) {
        this.dstHostSrvDiffHostRate = dstHostSrvDiffHostRate;
    }

    public Integer getDstHostSerrorRate() {
        return dstHostSerrorRate;
    }

    public void setDstHostSerrorRate(Integer dstHostSerrorRate) {
        this.dstHostSerrorRate = dstHostSerrorRate;
    }

    public Integer getDstHostSrvSerrorRate() {
        return dstHostSrvSerrorRate;
    }

    public void setDstHostSrvSerrorRate(Integer dstHostSrvSerrorRate) {
        this.dstHostSrvSerrorRate = dstHostSrvSerrorRate;
    }

    public Integer getDstHostRerrorRate() {
        return dstHostRerrorRate;
    }

    public void setDstHostRerrorRate(Integer dstHostRerrorRate) {
        this.dstHostRerrorRate = dstHostRerrorRate;
    }

    public Integer getDstHostSrvRerrorRate() {
        return dstHostSrvRerrorRate;
    }

    public void setDstHostSrvRerrorRate(Integer dstHostSrvRerrorRate) {
        this.dstHostSrvRerrorRate = dstHostSrvRerrorRate;
    }

    public Connection(){}

    public Integer getDuration() {
        return duration;
    }

    public void setDuration(Integer duration) {
        this.duration = duration;
    }

    public Integer getProtocolType() {
        return protocolType;
    }

    public void setProtocolType(Integer protocolType) {
        this.protocolType = protocolType;
    }

    public Integer getService() {
        return service;
    }

    public void setService(Integer service) {
        this.service = service;
    }

    public Integer getFlag() {
        return flag;
    }

    public void setFlag(Integer flag) {
        this.flag = flag;
    }

    public Integer getSrcBytes() {
        return srcBytes;
    }

    public void setSrcBytes(Integer srcBytes) {
        this.srcBytes = srcBytes;
    }

    public Integer getDstBytes() {
        return dstBytes;
    }

    public void setDstBytes(Integer dstBytes) {
        this.dstBytes = dstBytes;
    }

    public Integer getLand() {
        return land;
    }

    public void setLand(Integer land) {
        this.land = land;
    }

    public Integer getWrongFragment() {
        return wrongFragment;
    }

    public void setWrongFragment(Integer wrongFragment) {
        this.wrongFragment = wrongFragment;
    }

    public Integer getUrgent() {
        return urgent;
    }

    public void setUrgent(Integer urgent) {
        this.urgent = urgent;
    }

    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }

    public Integer getSrvCount() {
        return srvCount;
    }

    public void setSrvCount(Integer srvCount) {
        this.srvCount = srvCount;
    }

    public Integer getSerrorRate() {
        return serrorRate;
    }

    public void setSerrorRate(Integer serrorRate) {
        this.serrorRate = serrorRate;
    }

    public Integer getSrvSerrorRate() {
        return srvSerrorRate;
    }

    public void setSrvSerrorRate(Integer srvSerrorRate) {
        this.srvSerrorRate = srvSerrorRate;
    }

    public Integer getRerrorRate() {
        return rerrorRate;
    }

    public void setRerrorRate(Integer rerrorRate) {
        this.rerrorRate = rerrorRate;
    }

    public Integer getSrvRerrorRate() {
        return srvRerrorRate;
    }

    public void setSrvRerrorRate(Integer srvRerrorRate) {
        this.srvRerrorRate = srvRerrorRate;
    }

    public Integer getSameSrvRate() {
        return sameSrvRate;
    }

    public void setSameSrvRate(Integer sameSrvRate) {
        this.sameSrvRate = sameSrvRate;
    }

    public Integer getDiffSrvRate() {
        return diffSrvRate;
    }

    public void setDiffSrvRate(Integer diffSrvRate) {
        this.diffSrvRate = diffSrvRate;
    }

    public Integer getSrvDiffHostRate() {
        return srvDiffHostRate;
    }

    public void setSrvDiffHostRate(Integer srvDiffHostRate) {
        this.srvDiffHostRate = srvDiffHostRate;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public Connection(Integer duration, Integer protocolType, Integer service, Integer flag, Integer srcBytes, Integer dstBytes, Integer land, Integer wrongFragment, Integer urgent, Integer count, Integer srvCount, Integer serrorRate, Integer srvSerrorRate, Integer rerrorRate, Integer srvRerrorRate, Integer sameSrvRate, Integer diffSrvRate, Integer srvDiffHostRate, String label) {
        this.duration = duration;
        this.protocolType = protocolType;
        this.service = service;
        this.flag = flag;
        this.srcBytes = srcBytes;
        this.dstBytes = dstBytes;
        this.land = land;
        this.wrongFragment = wrongFragment;
        this.urgent = urgent;
        this.count = count;
        this.srvCount = srvCount;
        this.serrorRate = serrorRate;
        this.srvSerrorRate = srvSerrorRate;
        this.rerrorRate = rerrorRate;
        this.srvRerrorRate = srvRerrorRate;
        this.sameSrvRate = sameSrvRate;
        this.diffSrvRate = diffSrvRate;
        this.srvDiffHostRate = srvDiffHostRate;
        this.label = label;
    }
}
