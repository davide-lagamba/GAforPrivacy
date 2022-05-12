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


    public static void plotStatistics(ArrayList<int[]> rules, ArrayList<Connection> l){
        ArrayList<int[]> rulesTmp;
        for(int i=1; i<= rules.size();i++){
            rulesTmp= new ArrayList<int[]>(rules.subList(0, i));
        ArrayList<Double> results= performanceRuleSet(rulesTmp, l);
        Double TP= results.get(0);
        Double TN= results.get(1);
        Double FP= results.get(2);
        Double FN= results.get(3);
        Double falseAlarms= (FP)/(TN+FP);
        Double fmeasure= (TP)/(TP+(FP+FN)/2);
        Double detectionRate= (TP)/(FN+TP);
        Double accuracy= ((TP+TN)/(TP+TN+FP+FN));
        Double precision = (TP)/(TP+FP);
        Double specificity=TN/(TN+FP);
        Double MCC= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));
        System.out.println("N. of rules: "+(i)+" - Detection Rate: "+detectionRate+" - F-Measure: "+fmeasure+" - Precision: "+precision+" - Accuracy: "+accuracy+" - Specificity: "+specificity+" - MCC: "+MCC+" - False Alarms: "+falseAlarms);
        }
    }

    public static void plotConfusionMatrixCSV(ArrayList<int[]> rules, ArrayList<Connection> l){
        ArrayList<int[]> rulesTmp;
        System.out.println("N. di regole,True Positive,True Negative,False Positive,False Negative");
        for(int i=1; i<= rules.size();i++){
            rulesTmp= new ArrayList<int[]>(rules.subList(0, i));
            ArrayList<Double> results= performanceRuleSet(rulesTmp, (ArrayList<Connection>) l);
            Double TP= results.get(0);
            Double TN= results.get(1);
            Double FP= results.get(2);
            Double FN= results.get(3);

            System.out.println(""+i+","+TP+","+TN+","+FP+","+FN);
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
    private static List<Connection> lValidation;
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
        if(ruleSet.isEmpty()){
            return list;
        }
        ArrayList<Connection> result= new ArrayList<>();
        int t;
        for(Connection c: list){
            t=0;
            for(int[] g: ruleSet){
                if(!compareConnectionWithRule(c, g)){
                    t++;}
        }
            if(c.getLabel().equalsIgnoreCase("normal") || t==ruleSet.size()){
                result.add(c);
            }
    }
        return result;}

    static List<Connection> missingOnlyAttacksList(List<Connection> list, ArrayList<int[]> ruleSet){
        if(ruleSet.isEmpty()){
            return list;
        }
        ArrayList<Connection> result= new ArrayList<>();
        int t;
        for(Connection c: list){
            t=0;
            for(int[] g: ruleSet){
                if(!compareConnectionWithRule(c, g)){
                    t++;}
            }
            if(t== ruleSet.size() && !(c.getLabel().equals("normal"))){
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

    static HashMap<String, Integer> findAttacks(ArrayList<Connection> l){

        HashMap<String, Integer> mapAttacksTmp = new HashMap<>();
        int n=0;
        for(Connection c: l){
            String label= c.getLabel();
            if(!(label.equalsIgnoreCase("normal")))
               {
                n=0;
                if(mapAttacksTmp.containsKey(label)){
                    n=mapAttacksTmp.get(label);
                }
                   mapAttacksTmp.put(label, n+1);
            }
        }
        return mapAttacksTmp;
    }

    public static ArrayList<Connection> get90percentDataset(ArrayList<Connection> l10p, ArrayList<Connection> l100p){
        ArrayList<Connection> l90p= (ArrayList<Connection>) l100p.clone();
        for(Connection c: l10p){
            if(l90p.contains(c)){
                l90p.remove(c);
            }
        }
    return l90p;
    }
    public static void main(String[] args) throws IOException {
        l=DatasetLoader.parse(new File("src/main/resources/kddcup99_csv.csv"));
        lValidation=DatasetLoader.parse(new File("src/main/resources/kddcup.data.corrected.labeled.csv"));
        System.out.println(l.size());
        System.out.println(lValidation.size());
        lValidation=get90percentDataset((ArrayList<Connection>) l, (ArrayList<Connection>) lValidation);
        System.out.println(lValidation.size());

        System.out.println(l.size());
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
        ArrayList<int[]> bestRules= new ArrayList<>();
        int[] bestRuleDos1= new int[]{44599, 2, 12, 1, 101, 2233, 0, 3, 0, 0, 1, 100, 11, 58, 29, 1, 92, 99, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 2, 1, 1};
        int[] bestRuleDos2= new int[]{8169, 1, 12, 5, 411, 6640, 0, 2, 0, 1, 0, 1, 53, 100, 38, 100, 100, 100, 1, 1, 1, 1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1};
        int[] bestRuleDos3= new int[]{36280, 1, 6, 5, 265, 7538, 0, 3, 0, 0, 78, 22, 2, 68, 38, 100, 83, 78, 1, 1, 1, 1, 2, 2, 1, 2, 2, 1, 1, 1, 1, 1};
        int[] bestRuleDos4= new int[]{42790, 1, 12, 3, 428, 3993, 0, 0, 0, 0, 83, 36, 26, 10, 11, 0, 100, 77, 1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 2, 2, 1, 1};
        int[] bestRuleDos5= new int[]{50839, 1, 11, 3, 245, 1966, 0, 1, 1, 83, 25, 79, 70, 25, 69, 0, 100, 67, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 2, 2, 1, 1};
        int[] bestRuleDos6= new int[]{41847, 1, 15, 3, 177, 885, 0, 3, 0, 5, 75, 64, 18, 48, 45, 71, 83, 30, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 2, 1, 1, 1};
        int[] bestRuleDos7= new int[]{26236, 1, 1, 5, 497, 6935, 0, 0, 2, 2, 84, 65, 1, 100, 59, 0, 100, 78, 1, 1, 1, 1, 1, 2, 1, 2, 2, 1, 1, 2, 1, 1};
        int[] bestRuleDos8= new int[]{37018, 1, 3, 5, 748, 6703, 0, 2, 1, 2, 90, 27, 52, 69, 86, 100, 84, 73, 1, 1, 1, 1, 1, 2, 1, 2, 2, 1, 1, 1, 1, 1};
        int[] bestRuleDos9= new int[]{10230, 1, 11, 5, 702, 6262, 0, 2, 0, 2, 28, 100, 21, 100, 78, 31, 100, 100, 1, 1, 1, 1, 2, 2, 1, 1, 2, 1, 1, 1, 1, 1};
        int[] bestRuleDos10= new int[]{327, 1, 1, 1, 795, 6569, 0, 3, 0, 26, 51, 83, 96, 93, 89, 66, 84, 100, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1};
        int[] bestRuleDos11= new int[]{38945, 1, 14, 5, 778, 8217, 0, 1, 1, 0, 0, 4, 8, 46, 24, 100, 84, 100, 1, 1, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1, 1, 1};
        int[] bestRuleProbe1= new int[]{18216, 2, 0, 2, 0, 789, 4, 7, 0, 82, 94, 255, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2};
        int[] bestRuleProbe2= new int[]{21414, 4637, 0, 0, 2, 21, 12, 6, 100, 100, 74, 0, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2};
        int[] bestRuleProbe3= new int[]{29100, 15, 1, 0, 0, 1, 25, 0, 0, 0, 13, 18, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 1, 1};
        int[] bestRuleProbe4= new int[]{43096, 8352, 0, 0, 0, 578, 27, 6, 100, 57, 0, 0, 8, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 2, 2};
        int[] bestRuleU2r1= new int[]{42702, 6, 7291, 1, 0, 2, 714, 2, 6, 57, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        int[] bestRuleU2r2= new int[]{25584, 334, 9141, 0, 0, 2, 788, 26, 0, 1, 0, 1, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1};
        bestRules.add(bestRuleDos1);
        bestRules.add(bestRuleDos2);
        bestRules.add(bestRuleDos3);
        bestRules.add(bestRuleDos4);
        bestRules.add(bestRuleDos5);
        bestRules.add(bestRuleDos6);
        bestRules.add(bestRuleDos7);
        bestRules.add(bestRuleDos8);
        bestRules.add(bestRuleDos9);
        bestRules.add(bestRuleDos10);
        bestRules.add(bestRuleDos11);
        bestRules.add(bestRuleProbe1);
        bestRules.add(bestRuleProbe2);
        bestRules.add(bestRuleProbe3);
        bestRules.add(bestRuleProbe4);
        bestRules.add(bestRuleU2r1);
        bestRules.add(bestRuleU2r2);

        System.out.println("//// TRAINING /////");
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
        ArrayList<Connection> missingAttacksList= (ArrayList<Connection>) missingOnlyAttacksList(l, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //Probe
        ArrayList<Connection> lProbe=filterProbe((ArrayList<Connection>) l);
        results= performanceRuleSet(bestRules, lProbe);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Probe: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksProbe = findMissingAttacks(findAttacks(lProbe), mapFound);
        System.out.println("Attacchi mancanti Probe: "+mapMissingAttacksProbe.toString());
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
        missingAttacksList= (ArrayList<Connection>) missingOnlyAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //Dos
        ArrayList<Connection> lDos=filterDos((ArrayList<Connection>) l);
        results= performanceRuleSet(bestRules, lDos);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Dos: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksDos = findMissingAttacks(findAttacks(lDos), mapFound);
        System.out.println("Attacchi mancanti Dos: "+mapMissingAttacksDos.toString());
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
        missingAttacksList= (ArrayList<Connection>) missingOnlyAttacksList(lDos, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //U2R
        ArrayList<Connection> lU2r=filterU2r((ArrayList<Connection>) l);
        results= performanceRuleSet(bestRules, lU2r);
        System.out.println("////////////");
        System.out.println("Attacchi trovati U2r: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksU2r = findMissingAttacks(findAttacks(lU2r), mapFound);
        System.out.println("Attacchi mancanti U2r: "+mapMissingAttacksU2r.toString());
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
        missingAttacksList= (ArrayList<Connection>) missingOnlyAttacksList(lU2r, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //R2L
        ArrayList<Connection> lR2l=filterR2l((ArrayList<Connection>) l);
        results= performanceRuleSet(bestRules, lR2l);
        System.out.println("////////////");
        System.out.println("Attacchi trovati R2l: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksR2l = findMissingAttacks(findAttacks(lR2l), mapFound);
        System.out.println("Attacchi mancanti R2l: "+mapMissingAttacksR2l.toString());
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
        missingAttacksList= (ArrayList<Connection>) missingOnlyAttacksList(lR2l, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());
        plotStatistics(bestRules, (ArrayList<Connection>) l);
        plotConfusionMatrixCSV(bestRules, (ArrayList<Connection>) l);

//VALIDATION


        System.out.println("//// VALIDATION /////");
        mapAttacks.clear();
        mapFound.clear();
        System.out.println(lValidation.size());
        A=B=0.0;
        n=0;
        for(Connection c: lValidation){
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
        ArrayList<Double> resultsValidation= performanceRuleSet(bestRules, (ArrayList<Connection>) lValidation);
        System.out.println("Attacchi trovati: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksValidation = findMissingAttacks(mapAttacks, mapFound);
        System.out.println("Attacchi mancanti: "+mapMissingAttacksValidation.toString());
         TP= resultsValidation.get(0);
         TN= resultsValidation.get(1);
         FP= resultsValidation.get(2);
         FN= resultsValidation.get(3);
         fmeasure= (TP)/(TP+(FP+FN)/2);
         accuracy= ((TP+TN)/(TP+TN+FP+FN));
         detectionRate= (TP)/(FN+TP);
         falseAlarms= (FP)/(TN+FP);
         precision = (TP)/(TP+FP);
         specificity=TN/(TN+FP);
         MCC= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);
        System.out.println("F-Measure: "+fmeasure);
        HashMap<String, Double> attacksPercentageValidation= findAttackPercentages(mapAttacks, mapFound);
        System.out.println("Percentuali tipi di attacchi trovati:\n"+attacksPercentageValidation.toString());
        System.out.println("Numero di regole concatenate: "+bestRules.size());
        ArrayList<Connection> missingAttacksListValidation= (ArrayList<Connection>) missingOnlyAttacksList(lValidation, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksListValidation.size());

        //Probe
        ArrayList<Connection> lProbeValidation=filterProbe((ArrayList<Connection>) lValidation);
        resultsValidation= performanceRuleSet(bestRules, lProbeValidation);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Probe: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksProbeValidation = findMissingAttacks(findAttacks(lProbeValidation), mapFound);
        System.out.println("Attacchi mancanti Probe: "+mapMissingAttacksProbeValidation.toString());
        TP= resultsValidation.get(0);
        TN= resultsValidation.get(1);
        FP= resultsValidation.get(2);
        FN= resultsValidation.get(3);
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
        missingAttacksListValidation= (ArrayList<Connection>) missingOnlyAttacksList(lProbeValidation, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksListValidation.size());

        //Dos
        ArrayList<Connection> lDosValidation=filterDos((ArrayList<Connection>) lValidation);
        resultsValidation= performanceRuleSet(bestRules, lDosValidation);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Dos: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksDosValidation = findMissingAttacks(findAttacks(lDosValidation), mapFound);
        System.out.println("Attacchi mancanti Dos: "+mapMissingAttacksDosValidation.toString());
        TP= resultsValidation.get(0);
        TN= resultsValidation.get(1);
        FP= resultsValidation.get(2);
        FN= resultsValidation.get(3);
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
        missingAttacksListValidation= (ArrayList<Connection>) missingOnlyAttacksList(lDosValidation, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksListValidation.size());

        //U2R
        ArrayList<Connection> lU2rValidation=filterU2r((ArrayList<Connection>) lValidation);
        resultsValidation= performanceRuleSet(bestRules, lU2rValidation);
        System.out.println("////////////");
        System.out.println("Attacchi trovati U2r: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksU2rValidation = findMissingAttacks(findAttacks(lU2rValidation), mapFound);
        System.out.println("Attacchi mancanti U2r: "+mapMissingAttacksU2rValidation.toString());
        TP= resultsValidation.get(0);
        TN= resultsValidation.get(1);
        FP= resultsValidation.get(2);
        FN= resultsValidation.get(3);
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
        missingAttacksListValidation= (ArrayList<Connection>) missingOnlyAttacksList(lU2rValidation, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksListValidation.size());

        //R2L
        ArrayList<Connection> lR2lValidation=filterR2l((ArrayList<Connection>) lValidation);
        resultsValidation= performanceRuleSet(bestRules, lR2lValidation);
        System.out.println("////////////");
        System.out.println("Attacchi trovati R2l: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksR2lValidation = findMissingAttacks(findAttacks(lR2lValidation), mapFound);
        System.out.println("Attacchi mancanti R2l: "+mapMissingAttacksR2lValidation.toString());
        TP= resultsValidation.get(0);
        TN= resultsValidation.get(1);
        FP= resultsValidation.get(2);
        FN= resultsValidation.get(3);
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
        missingAttacksListValidation= (ArrayList<Connection>) missingOnlyAttacksList(lR2lValidation, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksListValidation.size());
        plotStatistics(bestRules, (ArrayList<Connection>) lValidation);
        plotConfusionMatrixCSV(bestRules, (ArrayList<Connection>) lValidation);
    }
}
