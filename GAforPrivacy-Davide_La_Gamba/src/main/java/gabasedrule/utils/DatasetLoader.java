package gabasedrule.utils;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class DatasetLoader {

    public static List<Connection> parse(final File file)
            throws IOException, IllegalArgumentException {
        var connessioni = new ArrayList<Connection>();
        CSVFormat csvFormat =
                CSVFormat.Builder.create().setHeader(
                                "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
                                "lnum_compromised","lroot_shell","lsu_attempted","lnum_root","lnum_file_creations","lnum_shells","lnum_access_files","lnum_outbound_cmds",
                        "is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
                                "srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
                                "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label")
                        .setDelimiter(',').build();
        var records =
                csvFormat.parse(new FileReader(file));
        int riga = 1;
        for (CSVRecord record : records) {
            if (!record.isConsistent()) {
                throw new IllegalArgumentException("errore nella compilazione "
                        + "del dataset");
            }
            if (riga == 1) {
                riga++;
                continue;
            }
            Connection connection = new Connection();
            connection.setDuration(Integer.parseInt(record.get(Connection.COLUMN_DURATION)));
            connection.setProtocolType(Connection.protocolTypeMap.get(record.get(Connection.COLUMN_PROTOCOL_TYPE)));
            connection.setService(Connection.serviceMap.get(record.get(Connection.COLUMN_SERVICE)));
            connection.setFlag(Connection.flagMap.get(record.get(Connection.COLUMN_FLAG)));
            connection.setSrcBytes(Integer.parseInt(record.get(Connection.COLUMN_SRC_BYTES)));
            connection.setDstBytes(Integer.parseInt(record.get(Connection.COLUMN_DST_BYTES)));
            connection.setLand(Integer.parseInt(record.get(Connection.COLUMN_LAND)));
            connection.setWrongFragment(Integer.parseInt(record.get(Connection.COLUMN_WRONG_FRAGMENT)));
            connection.setUrgent(Integer.parseInt(record.get(Connection.COLUMN_URGENT)));
            connection.setCount(Integer.parseInt(record.get(Connection.COLUMN_COUNT)));
            connection.setSrvCount(Integer.parseInt(record.get(Connection.COLUMN_SRV_COUNT)));
            connection.setSerrorRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_SERROR_RATE)) *100));
            connection.setSrvSerrorRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_SRV_SERROR_RATE))*100));
            connection.setRerrorRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_RERROR_RATE))*100));
            connection.setSrvRerrorRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_SRV_RERROR_RATE))*100));
            connection.setSameSrvRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_SAME_SRV_RATE))*100));
            connection.setDiffSrvRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DIFF_SRV_RATE))*100));
            connection.setSrvDiffHostRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_SRV_DIFF_HOST_RATE))*100));
            connection.setHot(Integer.parseInt(record.get(Connection.COLUMN_HOT)));
            connection.setNumFailedLogins(Integer.parseInt(record.get(Connection.COLUMN_NUM_FAILED_LOGINS)));
            connection.setLoggedIn(Integer.parseInt(record.get(Connection.COLUMN_LOGGED_IN)));
            connection.setNumCompromised(Integer.parseInt(record.get(Connection.COLUMN_NUM_COMPROMISED)));
            connection.setRootShell(Integer.parseInt(record.get(Connection.COLUMN_ROOT_SHELL)));
            connection.setSuAttempted(Integer.parseInt(record.get(Connection.COLUMN_SU_ATTEMPTED)));
            connection.setNumRoot(Integer.parseInt(record.get(Connection.COLUMN_NUM_ROOT)));
            connection.setNumFilesCreations(Integer.parseInt(record.get(Connection.COLUMN_NUM_FILES_CREATIONS)));
            connection.setNumShells(Integer.parseInt(record.get(Connection.COLUMN_NUM_SHELLS)));
            connection.setNumAccessFiles(Integer.parseInt(record.get(Connection.COLUMN_NUM_ACCESS_FILES)));
            connection.setNumOutboundCmds(Integer.parseInt(record.get(Connection.COLUMN_NUM_OUTBOUND_CMDS)));
            connection.setIsHostLogin(Integer.parseInt(record.get(Connection.COLUMN_IS_HOST_LOGIN)));
            connection.setIsGuestLogin(Integer.parseInt(record.get(Connection.COLUMN_IS_GUEST_LOGIN)));
            connection.setDstHostCount(Integer.parseInt(record.get(Connection.COLUMN_DST_HOST_COUNT)));
            connection.setDstHostSrvCount(Integer.parseInt(record.get(Connection.COLUMN_DST_HOST_SRV_COUNT)));
            connection.setDstHostSameSrvRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DST_HOST_SAME_SRV_RATE))*100));
            connection.setDstHostDiffSrvRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DST_HOST_DIFF_SRV_RATE))*100));
            connection.setDstHomeSameSrcPortRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DST_HOME_SAME_SRC_PORT_RATE))*100));
            connection.setDstHostSrvDiffHostRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DST_HOST_SRV_DIFF_HOST_RATE))*100));
            connection.setDstHostSerrorRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DST_HOST_SERROR_RATE))*100));
            connection.setDstHostSrvSerrorRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DST_HOST_SRV_SERROR_RATE))*100));
            connection.setDstHostRerrorRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DST_HOST_RERROR_RATE))*100));
            connection.setDstHostSrvRerrorRate((int) Math.round(Double.parseDouble(record.get(Connection.COLUMN_DST_HOST_SRV_RERROR_RATE))*100));

            connection.setLabel(record.get(Connection.COLUMN_LABEL));

            connessioni.add(connection);
        }
        return connessioni;
    }
}