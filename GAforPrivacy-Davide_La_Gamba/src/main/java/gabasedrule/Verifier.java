package gabasedrule;

import gabasedrule.utils.Connection;
import gabasedrule.utils.DatasetLoader;
import io.jenetics.*;
import io.jenetics.engine.Engine;
import io.jenetics.engine.EvolutionStatistics;
import io.jenetics.util.Factory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import static io.jenetics.engine.EvolutionResult.toBestPhenotype;

public class Verifier {

    public static final Integer EQUALS=3;
    public static Double A;
    public static Double B;
    private static HashMap<String, Integer> mapAttacks = new HashMap<>();
    private static HashMap<String, Integer> mapFound = new HashMap<>();


    public static void plotStatistics(ArrayList<int[]> rules){
        ArrayList<int[]> rulesTmp;
        for(int i=1; i<= rules.size();i++){
            rulesTmp= new ArrayList<int[]>(rules.subList(0, i));
        ArrayList<Double> results= performanceRuleSet(rulesTmp, (ArrayList<Connection>) l);
        Double TP= results.get(0);
        Double TN= results.get(1);
        Double FP= results.get(2);
        Double FN= results.get(3);
        Double fmeasure= (TP)/(TP+(FP+FN)/2);
        Double detectionRate= (TP)/(FN+TP);
        Double accuracy= ((TP+TN)/(TP+TN+FP+FN));
        Double precision = (TP)/(TP+FP);
        Double specificity=TN/(TN+FP);
        Double MCC= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));
        System.out.println("N. of rules: "+(i)+" - Detection Rate: "+detectionRate+" - F-Measure: "+fmeasure+" - Precision: "+precision+" - Accuracy: "+accuracy+" - Specificity: "+specificity+" - MCC: "+MCC);
        }
    }
    public static ArrayList<Connection> filterProbe(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if((c.getLabel().equalsIgnoreCase("normal")) || (c.getLabel().equalsIgnoreCase("ipsweep")) || (c.getLabel().equalsIgnoreCase("nmap")) ||
                    (c.getLabel().equalsIgnoreCase("portsweep")) || (c.getLabel().equalsIgnoreCase("satan"))){
                l2.add(c);
            }
        }
        return l2;
    }

    public static ArrayList<Connection> filterDos(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if((c.getLabel().equalsIgnoreCase("normal")) || (c.getLabel().equalsIgnoreCase("back")) || (c.getLabel().equalsIgnoreCase("land")) || (c.getLabel().equalsIgnoreCase("neptune")) ||
                    (c.getLabel().equalsIgnoreCase("pod")) || (c.getLabel().equalsIgnoreCase("smurf")) || (c.getLabel().equalsIgnoreCase("teardrop"))){
                l2.add(c);
            }
        }
        return l2;
    }

    public static ArrayList<Connection> filterU2r(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if((c.getLabel().equalsIgnoreCase("normal")) || (c.getLabel().equalsIgnoreCase("buffer_overflow")) || (c.getLabel().equalsIgnoreCase("loadmodule")) || (c.getLabel().equalsIgnoreCase("perl")) ||
                    (c.getLabel().equalsIgnoreCase("rootkit"))){
                l2.add(c);
            }
        }
        return l2;
    }

    public static ArrayList<Connection> filterR2l(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if((c.getLabel().equalsIgnoreCase("normal")) || (c.getLabel().equalsIgnoreCase("ftp_write")) || (c.getLabel().equalsIgnoreCase("guess_passwd")) || (c.getLabel().equalsIgnoreCase("imap")) ||
                    (c.getLabel().equalsIgnoreCase("multihop")) || (c.getLabel().equalsIgnoreCase("phf")) || (c.getLabel().equalsIgnoreCase("spy")) ||
                    (c.getLabel().equalsIgnoreCase("warezclient")) || (c.getLabel().equalsIgnoreCase("warezmaster"))){
                l2.add(c);
            }
        }
        return l2;
    }

    public static HashMap<String, Double> findAttackPercentages(HashMap<String, Integer> allAttacks, HashMap<String, Integer> foundAttacks){
        Double dosTotal=0.0,  u2rTotal=0.0, r2lTotal=0.0, probeTotal=0.0;
        Double dos=0.0,  u2r=0.0, r2l=0.0, probe=0.0;
        Set<String> attacks= allAttacks.keySet();
        for(String s: attacks){
            if(s.equalsIgnoreCase("back")||s.equalsIgnoreCase("land")||s.equalsIgnoreCase("neptune")||s.equalsIgnoreCase("pod")||s.equalsIgnoreCase("smurf")||s.equalsIgnoreCase("teardrop")){
                dosTotal+=allAttacks.get(s);
                if(foundAttacks.containsKey(s))
                    dos+=foundAttacks.get(s);
            }
            if(s.equalsIgnoreCase("buffer_overflow")||s.equalsIgnoreCase("loadmodule")||s.equalsIgnoreCase("perl")||s.equalsIgnoreCase("rootkit")){
                u2rTotal+=allAttacks.get(s);
                if(foundAttacks.containsKey(s))
                    u2r+=foundAttacks.get(s);
            }

            if(s.equalsIgnoreCase("ftp_write")||s.equalsIgnoreCase("guess_passwd")||s.equalsIgnoreCase("imap")||s.equalsIgnoreCase("multihop")||s.equalsIgnoreCase("phf")||s.equalsIgnoreCase("spy")||s.equalsIgnoreCase("warezclient")||s.equalsIgnoreCase("warezmaster")){
                r2lTotal+=allAttacks.get(s);
                if(foundAttacks.containsKey(s))
                    r2l+=foundAttacks.get(s);
            }

            if(s.equalsIgnoreCase("ipsweep")||s.equalsIgnoreCase("nmap")||s.equalsIgnoreCase("portsweep")||s.equalsIgnoreCase("satan")){
                probeTotal+=allAttacks.get(s);
                if(foundAttacks.containsKey(s))
                    probe+=foundAttacks.get(s);
            }
        }
        HashMap<String, Double> results= new HashMap<>();
        results.put("dos", dos/dosTotal);
        results.put("u2r", u2r/u2rTotal);
        results.put("r2l", r2l/r2lTotal);
        results.put("probe", probe/probeTotal);
        return results;
    }

    static Boolean compare(Integer a, Integer b, Integer symbol){

        if(symbol==1){
            if(a<=b)
                return true;
            return false;
        }
        if(symbol==2){
            if(a>=b)
                return true;
            return false;}
        if(symbol==3){
            if(a==b)
                return true;
            return false;}
        return false;
        }

    private static List<Connection> l;
    static boolean compareConnectionWithRule(Connection c, int[] g){
        if(g.length>30){
        if((compare(c.getDuration(),g[0], g[18])) &&
                (compare(c.getProtocolType(),g[1], EQUALS)) &&
                (compare(c.getService(),g[2], EQUALS)) &&
                (compare(c.getFlag(), g[3], EQUALS)) &&
                (compare(c.getSrcBytes(), g[4], g[19])) &&
                (compare(c.getDstBytes(),g[5], g[20])) &&
                (compare(c.getLand(), g[6], EQUALS)) &&
                (compare(c.getWrongFragment(),g[7], g[21])) &&
                (compare(c.getUrgent(),g[8], g[22])) &&
                (compare(c.getCount(),g[9], g[23])) &&
                (compare(c.getSrvCount(),g[10], g[24])) &&
                (compare(c.getSerrorRate(),g[11], g[25])) &&
                (compare(c.getSrvSerrorRate(),g[12], g[26])) &&
                (compare(c.getRerrorRate(),g[13], g[27])) &&
                (compare(c.getSrvRerrorRate(),g[14], g[28])) &&
                (compare(c.getSameSrvRate(),g[15], g[29])) &&
                (compare(c.getDiffSrvRate(),g[16], g[30])) &&
                (compare(c.getSrvDiffHostRate(),g[17], g[31]))){
            return true;}else{
        return false;}}
        else if(g.length==22){
                if((compare(c.getDuration(),g[0], g[11])) &&
                        (compare(c.getSrcBytes(),g[1], g[12])) &&
                        (compare(c.getDstBytes(),g[2], g[13])) &&
                        (compare(c.getLoggedIn(),g[3], g[14])) &&
                        (compare(c.getSuAttempted(), g[4], g[15])) &&
                        (compare(c.getNumShells(), g[5], g[16])) &&
                        (compare(c.getNumRoot(),g[6], g[17])) &&
                        (compare(c.getNumFilesCreations(), g[7], g[18])) &&
                        (compare(c.getNumAccessFiles(),g[8], g[19])) &&
                        (compare(c.getSrvDiffHostRate(),g[9], g[20])) &&
                        (compare(c.getDstHostSrvDiffHostRate(),g[10], g[21]))
                       ){
                    return true;}else{
                    return false;}
                }
        else {
            if((compare(c.getDuration(),g[0], g[13])) &&
                    (compare(c.getDstBytes(),g[1], g[14])) &&
                    (compare(c.getLoggedIn(),g[2], g[15])) &&
                    (compare(c.getSuAttempted(), g[3], g[16])) &&
                    (compare(c.getNumShells(), g[4], g[17])) &&
                    (compare(c.getNumRoot(),g[5], g[18])) &&
                    (compare(c.getNumFilesCreations(), g[6], g[19])) &&
                    (compare(c.getNumAccessFiles(),g[7], g[20])) &&
                    (compare(c.getSrvDiffHostRate(),g[8], g[21])) &&
                    (compare(c.getDstHostSrvDiffHostRate(),g[9], g[22])) &&
                    (compare(c.getRerrorRate(),g[10], g[23])) &&
                    (compare(c.getDstHostCount(),g[11], g[24])) &&
                    (compare(c.getFlag(),g[12], EQUALS))){
                return true;}else{
                return false;}
        }

    }

    static ArrayList<Double> performanceRuleSet(ArrayList<int[]> ruleSet, ArrayList<Connection> list){
        Double TP=0.0, TN=0.0, FP=0.0, FN=0.0;
        mapFound.clear();
        int n=0;
        int tmp=0;
        String label="";
        for(Connection c: list){
            label=c.getLabel();
            for(int[] g: ruleSet){
                if(compareConnectionWithRule(c, g)) {
                    tmp++;

                }
            }
            if(c.getLabel().equalsIgnoreCase("normal")){
                if(tmp>0)
                    FP++;
                else
                    TN++;
            }else{
                if(tmp>0){
                    TP++;
                    n=0;
                    if(mapFound.containsKey(label)){
                        n=mapFound.get(label);
                    }
                    mapFound.put(label, n+1);
                }
                else
                    FN++;
            }
            tmp=0;
        }
        ArrayList<Double> results = new ArrayList<>();
        results.add(TP);
        results.add(TN);
        results.add(FP);
        results.add(FN);
        return results;
    }

    static List<Connection> missingAttacksList(List<Connection> list, ArrayList<int[]> ruleSet){
        ArrayList<Connection> result= new ArrayList<>();
        int t;
        for(Connection c: list){
            t=0;
            for(int[] g: ruleSet){
                if(!compareConnectionWithRule(c, g)){
                    t++;}
        }
            if(c.getLabel().equalsIgnoreCase("normal") || t== ruleSet.size()){
                result.add(c);
            }
    }
        return result;}


    static HashMap<String, Integer> findMissingAttacks(HashMap<String, Integer> total, HashMap<String, Integer> found){
        Set<String> attacchi=total.keySet();
        HashMap<String, Integer> missing= new HashMap<>();
        int n=0;
        for(String s:attacchi){
            n=total.get(s);
            if(found.containsKey(s)){
                n=n-found.get(s);
            }
            missing.put(s, n);
        }
        return missing;
    }
    public static void main(String[] args) throws IOException {
        l=DatasetLoader.parse(new File("src/main/resources/kddcup99_csv.csv"));
//        System.out.println(l.size());
        A=B=0.0;
        int n=0;
        for(Connection c: l){
            String label= c.getLabel();
            if(label.equalsIgnoreCase("normal"))
                B++;
            else {A++;
                n=0;
            if(mapAttacks.containsKey(label)){
                n=mapAttacks.get(label);
            }
            mapAttacks.put(label, n+1);
            }
        }
        System.out.println("Number of attacks in dataset: "+A+"\nNumber of normal connections: "+B);
        System.out.println("Attacchi totali in dataset: "+mapAttacks.toString());

        int[] bestDosNoNeptune= new int[]{4460,3,10,1,243,9956,0,0,0,1,0,33,31,15,13,78,13,100,1,2,1,2,2,2,2,1,1,1,1,2,1,1};
        int[] bestDosOnlyNeptune= new int[]{23461,1,12,5,494,4581,0,1,0,0,45,46,42,75,72,100,100,16,1,1,1,1,2,2,1,2,2,1,1,1,1,1}; //poco utile/
        int[] bestNoFilter= new int[]{44141,1,12,5,995,7680,0,2,0,0,28,2,41,96,75,0,100,9,1,1,1,1,1,2,1,2,2,1,1,2,1,1};
        int[] bestNoDos = new int[]{47494,1,11,3,189,8016,0,1,0,3,81,55,72,38,23,0,100,29,1,1,1,1,2,2,1,1,1,2,2,2,1,1};
        int[] bestProbe = new int[]{44907,1,11,3,925,3358,0,2,3,8,44,76,48,7,28,0,100,0,1,1,1,1,1,2,1,1,1,2,2,2,1,1}; //poco utile/
        int[] bestProbeNoPortsweep = new int[]{36830,1,11,3,402,9571,0,0,0,25,73,99,5,41,57,36,53,63,1,1,1,2,2,2,1,1,1,2,2,1,2,1};//poco utile/
        int[] bestRuleMissingNeptunes= new int[]{32065,1,12,3,689,7717,0,2,3,0,40,98,75,30,95,100,0,39,1,1,1,1,1,2,1,1,1,2,2,1,2,1};
        int[] bestRuleMissingTeardropAndIpSweep = new int[]{43302,3,8,1,23,589,0,3,2,0,1,100,86,0,0,0,100,100,1,1,1,1,1,2,2,1,1,2,1,2,1,1};
        ArrayList<int[]> bestRules= new ArrayList<>();
        bestRules.add(bestDosNoNeptune);
        bestRules.add(bestNoFilter);
        bestRules.add(bestNoDos);
        bestRules.add(bestRuleMissingNeptunes);
        bestRules.add(bestRuleMissingTeardropAndIpSweep);
        int[] bestRuleMissingPortsweep = new int[]{56520,1,12,8,253,1545,0,1,2,0,71,0,96,0,0,0,100,90,1,1,1,1,1,2,1,2,1,2,2,2,1,1};
        bestRules.add(bestRuleMissingPortsweep);
        int[] bestRuleMoreMissingPortsweep = new int[]{37345,1,11,8,248,1481,0,3,2,58,52,32,14,53,61,91,15,54,1,1,1,1,1,1,1,1,1,2,2,2,1,1};
        bestRules.add(bestRuleMoreMissingPortsweep);
        int[] bestRuleMissingBack = new int[]{37517,1,1,1,942,7598,0,1,1,53,57,73,52,85,0,20,99,100,1,2,2,1,1,1,1,1,1,1,2,2,1,1};
        bestRules.add(bestRuleMissingBack);
        int[] bestRuleMissingMoreNeptuneAndSatan = new int[]{54881,1,11,5,884,7806,0,3,0,0,31,1,8,100,71,100,100,72,1,1,1,1,2,2,1,2,2,1,1,1,1,1};
        bestRules.add(bestRuleMissingMoreNeptuneAndSatan);
        int[] bestRuleMissingWarezclient = new int[]{6055,1,14,1,246,8434,0,1,2,2,2,97,57,95,24,12,100,0,1,2,1,1,1,1,1,1,1,1,1,2,1,2}; //AGGIUNGE FALSI POSITIVI
        bestRules.add(bestRuleMissingWarezclient);
        int[] bestRuleMissingSatan = new int[]{6172,2,12,1,416,92,0,0,0,2,0,44,55,0,54,0,93,70,1,1,1,2,2,2,2,1,1,1,1,2,1,1}; //AGGIUNGE FALSI POSITIVI
        bestRules.add(bestRuleMissingSatan);
        int[] bestRuleMissingNmap = new int[]{43303,5808,0,0,0,920,24,6,0,17,43,2,11,1,1,1,1,2,1,1,1,2,1,1,2}; //Probe features/
        int[] bestRuleMoreMoreMissingPortsweep = new int[]{49018,24,0,0,1,232,12,1,81,93,63,73,8,1,1,2,2,1,1,1,1,1,1,2,2}; //Probe features
        bestRules.add(bestRuleMoreMoreMissingPortsweep);
        int[] bestRuleMoreProbe = new int[]{0,1303,1,2,0,840,14,5,2,0,26,23,3,1,1,1,1,1,1,1,1,1,2,2,2}; //Probe features
        bestRules.add(bestRuleMoreProbe);
        int[] bestRuleMoreMoreProbe = new int[]{13,125,1,0,0,0,0,0,0,0,98,255,1,1,1,1,2,1,1,1,1,1,2,1,1}; //Probe features, aggiunge molti FP/
        int[] bestRuleMorePortsweep = new int[]{44943,247,0,0,0,58,22,7,42,98,1,48,9,1,1,1,1,1,1,1,1,1,1,2,2}; //Probe features
        bestRules.add(bestRuleMorePortsweep);
        int[] bestRuleMoreNeptune = new int[]{15464,1,6,5,457,9114,0,0,0,0,37,33,13,72,76,0,83,56,1,1,1,2,2,2,1,2,2,1,1,2,1,1}; //Probe features
        bestRules.add(bestRuleMoreNeptune);
        int[] bestRuleMoreU2r = new int[]{14,6,7188,0,0,2,187,23,7,100,3,1,1,1,2,1,1,1,1,1,1,1}; //U2R features
        bestRules.add(bestRuleMoreU2r);
        int[] bestRuleMoreWarezclient = new int[]{15203,350,1184,0,0,0,56,21,7,100,0,1,2,2,2,1,2,1,1,1,1,1}; //U2R features
        bestRules.add(bestRuleMoreWarezclient);
        ArrayList<Double> results= performanceRuleSet(bestRules, (ArrayList<Connection>) l);
        System.out.println("Attacchi trovati: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacks = findMissingAttacks(mapAttacks, mapFound);
        System.out.println("Attacchi mancanti: "+mapMissingAttacks.toString());
        Double TP= results.get(0);
        Double TN= results.get(1);
        Double FP= results.get(2);
        Double FN= results.get(3);
        Double fmeasure= (TP)/(TP+(FP+FN)/2);
        Double accuracy= ((TP+TN)/(TP+TN+FP+FN));
        Double detectionRate= (TP)/(FN+TP);
        Double falseAlarms= (FP)/(TN+FP);
        Double precision = (TP)/(TP+FP);
        Double specificity=TN/(TN+FP);
        Double MCC= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);
        System.out.println("F-Measure: "+fmeasure);
        HashMap<String, Double> attacksPercentage= findAttackPercentages(mapAttacks, mapFound);
        System.out.println("Percentuali tipi di attacchi trovati:\n"+attacksPercentage.toString());
        System.out.println("Numero di regole concatenate: "+bestRules.size());
        ArrayList<Connection> missingAttacksList= (ArrayList<Connection>) missingAttacksList(l, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //Probe
        ArrayList<Connection> lProbe=filterProbe((ArrayList<Connection>) l);
        results= performanceRuleSet(bestRules, lProbe);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Probe: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksProbe = findMissingAttacks(mapAttacks, mapFound);
        System.out.println("Attacchi mancanti Probe: "+mapMissingAttacks.toString());
        TP= results.get(0);
        TN= results.get(1);
        FP= results.get(2);
        FN= results.get(3);
        fmeasure= (TP)/(TP+(FP+FN)/2);
        accuracy= ((TP+TN)/(TP+TN+FP+FN));
        detectionRate= (TP)/(FN+TP);
        falseAlarms= (FP)/(TN+FP);
        precision = (TP)/(TP+FP);
        specificity=TN/(TN+FP);
        MCC= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));
        System.out.println("Risultati relativi ad attacchi Probe:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);
        System.out.println("F-Measure: "+fmeasure);
        System.out.println("Numero di regole concatenate: "+bestRules.size());
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //Dos
        ArrayList<Connection> lDos=filterDos((ArrayList<Connection>) l);
        results= performanceRuleSet(bestRules, lDos);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Dos: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksDos = findMissingAttacks(mapAttacks, mapFound);
        System.out.println("Attacchi mancanti Dos: "+mapMissingAttacks.toString());
        TP= results.get(0);
        TN= results.get(1);
        FP= results.get(2);
        FN= results.get(3);
        fmeasure= (TP)/(TP+(FP+FN)/2);
        accuracy= ((TP+TN)/(TP+TN+FP+FN));
        detectionRate= (TP)/(FN+TP);
        falseAlarms= (FP)/(TN+FP);
        precision = (TP)/(TP+FP);
        specificity=TN/(TN+FP);
        MCC= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));
        System.out.println("Risultati relativi ad attacchi Dos:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);
        System.out.println("F-Measure: "+fmeasure);
        System.out.println("Numero di regole concatenate: "+bestRules.size());
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //U2R
        ArrayList<Connection> lU2r=filterU2r((ArrayList<Connection>) l);
        results= performanceRuleSet(bestRules, lU2r);
        System.out.println("////////////");
        System.out.println("Attacchi trovati U2r: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksU2r = findMissingAttacks(mapAttacks, mapFound);
        System.out.println("Attacchi mancanti U2r: "+mapMissingAttacks.toString());
        TP= results.get(0);
        TN= results.get(1);
        FP= results.get(2);
        FN= results.get(3);
        fmeasure= (TP)/(TP+(FP+FN)/2);
        accuracy= ((TP+TN)/(TP+TN+FP+FN));
        detectionRate= (TP)/(FN+TP);
        falseAlarms= (FP)/(TN+FP);
        precision = (TP)/(TP+FP);
        specificity=TN/(TN+FP);
        MCC= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));
        System.out.println("Risultati relativi ad attacchi U2r:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);
        System.out.println("F-Measure: "+fmeasure);
        System.out.println("Numero di regole concatenate: "+bestRules.size());
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //R2L
        ArrayList<Connection> lR2l=filterR2l((ArrayList<Connection>) l);
        results= performanceRuleSet(bestRules, lR2l);
        System.out.println("////////////");
        System.out.println("Attacchi trovati R2l: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksR2l = findMissingAttacks(mapAttacks, mapFound);
        System.out.println("Attacchi mancanti R2l: "+mapMissingAttacks.toString());
        TP= results.get(0);
        TN= results.get(1);
        FP= results.get(2);
        FN= results.get(3);
        fmeasure= (TP)/(TP+(FP+FN)/2);
        accuracy= ((TP+TN)/(TP+TN+FP+FN));
        detectionRate= (TP)/(FN+TP);
        falseAlarms= (FP)/(TN+FP);
        precision = (TP)/(TP+FP);
        specificity=TN/(TN+FP);
        MCC= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));
        System.out.println("Risultati relativi ad attacchi R2l:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);
        System.out.println("F-Measure: "+fmeasure);
        System.out.println("Numero di regole concatenate: "+bestRules.size());
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());
        plotStatistics(bestRules);
    }
}
