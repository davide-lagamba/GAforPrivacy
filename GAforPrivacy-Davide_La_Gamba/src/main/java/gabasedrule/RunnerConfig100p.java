package gabasedrule;

import gabasedrule.utils.Connection;
import gabasedrule.utils.DatasetLoader;
import io.jenetics.*;
import io.jenetics.engine.Engine;
import io.jenetics.engine.EvolutionStatistics;
import io.jenetics.util.Factory;

import java.io.File;
import java.io.IOException;
import java.util.*;

import static gabasedrule.Verifier.*;
import static io.jenetics.engine.EvolutionResult.toBestPhenotype;

public class RunnerConfig100p {

    public static final Integer EQUALS=3;
    public static final Integer LESSER=1;
    public static final Integer GREATER=2;
    public static Double A;
    public static Double At;
    public static Double B;
    public static Double Bt;
    private static HashMap<String, Integer> mapAttacks = new HashMap<>();
    private static HashMap<String, Integer> mapAttacksV = new HashMap<>();
    private static HashMap<String, Integer> mapAttacks2 = new HashMap<>();
    private static HashMap<String, Integer> mapFound = new HashMap<>();
    private static HashMap<String, Integer> mapFoundTmp = new HashMap<>();
    private static Double bestFitness=0.0;
    private static ArrayList<int[]> bestRules= new ArrayList<>();

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
        public static ArrayList<Connection> filterDos(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if((c.getLabel().equalsIgnoreCase("normal")) || (c.getLabel().equalsIgnoreCase("neptune")) || (c.getLabel().equalsIgnoreCase("land")) ||
                    (c.getLabel().equalsIgnoreCase("back")) || (c.getLabel().equalsIgnoreCase("pod")) || (c.getLabel().equalsIgnoreCase("smurf")) ||
                    (c.getLabel().equalsIgnoreCase("teardrop"))){
                l2.add(c);
            }
        }
        return l2;
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

    public static ArrayList<Connection> filterProbeNoPortsweep(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if((c.getLabel().equalsIgnoreCase("normal")) || (c.getLabel().equalsIgnoreCase("ipsweep")) || (c.getLabel().equalsIgnoreCase("nmap")) ||
                    (c.getLabel().equalsIgnoreCase("satan"))){
                l2.add(c);
            }
        }
        return l2;
    }

    public static ArrayList<Connection> filterNoDos(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if(!((c.getLabel().equalsIgnoreCase("neptune")) || (c.getLabel().equalsIgnoreCase("land")) ||
                    (c.getLabel().equalsIgnoreCase("back")) || (c.getLabel().equalsIgnoreCase("pod")) || (c.getLabel().equalsIgnoreCase("smurf")) ||
                    (c.getLabel().equalsIgnoreCase("teardrop")))){
                l2.add(c);
            }
        }
        return l2;
    }
    public static ArrayList<Connection> filterDosNoNeptune(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if((c.getLabel().equalsIgnoreCase("normal")) || (c.getLabel().equalsIgnoreCase("land")) ||
                    (c.getLabel().equalsIgnoreCase("back")) || (c.getLabel().equalsIgnoreCase("pod")) || (c.getLabel().equalsIgnoreCase("smurf")) ||
                    (c.getLabel().equalsIgnoreCase("teardrop"))){
                l2.add(c);
            }
        }
        return l2;
    }



    public static ArrayList<Connection> filterDosNeptune(ArrayList<Connection> l){
        ArrayList<Connection> l2= new ArrayList<>();
        for(Connection c: l){
            if((c.getLabel().equalsIgnoreCase("normal")) || (c.getLabel().equalsIgnoreCase("neptune"))){
                l2.add(c);
            }
        }
        return l2;
    }

    private static List<Connection> l= new ArrayList<>();
    private static List<Connection> lCopy= new ArrayList<>();
    private static List<Connection> lValidation= new ArrayList<>();
    private static List<Connection> lTotale;



    static  void createTrainingAndValidationSetsNoSave() throws IOException {
        Collections.shuffle(l);
        int i=l.size()/10;
        lValidation= new ArrayList<Connection>();
        ArrayList<Connection> lTemp= new ArrayList<>();
        for(int j=0; j<l.size(); j++) {
            if (j <= i) {
                lTemp.add(l.get(j));
            } else {
                lValidation.add(l.get(j));
            }
        }
        l= (ArrayList<Connection>) lTemp.clone();
    }


    static int[] fromGenotypeToArrayDos(final Genotype<IntegerGene> gt){
        int[] outputRule = new int[]{gt.get(0).get(0).allele(), gt.get(1).get(0).allele(),gt.get(2).get(0).allele(),
                gt.get(3).get(0).allele(),gt.get(4).get(0).allele(),gt.get(5).get(0).allele(),
                gt.get(6).get(0).allele(),gt.get(7).get(0).allele(),gt.get(7).get(1).allele(),
                gt.get(8).get(0).allele(),gt.get(8).get(1).allele(),gt.get(9).get(0).allele(),
                gt.get(9).get(1).allele(),gt.get(9).get(2).allele(),gt.get(9).get(3).allele(),
                gt.get(9).get(4).allele(),gt.get(9).get(5).allele(),gt.get(9).get(6).allele(),
                gt.get(10).get(0).allele(),gt.get(10).get(1).allele(),gt.get(10).get(2).allele(),
                gt.get(10).get(3).allele(),gt.get(10).get(4).allele(),gt.get(10).get(5).allele(),
                gt.get(10).get(6).allele(),gt.get(10).get(7).allele(),gt.get(10).get(8).allele(),
                gt.get(10).get(9).allele(),gt.get(10).get(10).allele(),gt.get(10).get(11).allele(),
                gt.get(10).get(12).allele(),gt.get(10).get(13).allele()};
        return outputRule;
    }
    static int[] fromGenotypeToArrayProbe(final Genotype<IntegerGene> gt){
        int[] outputRule = new int[]{gt.get(0).get(0).allele(), gt.get(1).get(0).allele(),gt.get(2).get(0).allele(),
                gt.get(3).get(0).allele(),gt.get(3).get(1).allele(),gt.get(4).get(0).allele(),
                gt.get(5).get(0).allele(),gt.get(6).get(0).allele(),gt.get(7).get(0).allele(),
                gt.get(7).get(1).allele(),gt.get(7).get(2).allele(),gt.get(8).get(0).allele(),
                gt.get(9).get(0).allele(),gt.get(10).get(0).allele(),gt.get(10).get(1).allele(),
                gt.get(10).get(2).allele(),gt.get(10).get(3).allele(),gt.get(10).get(4).allele(),
                gt.get(10).get(5).allele(),gt.get(10).get(6).allele(),gt.get(10).get(7).allele(),
                gt.get(10).get(8).allele(),gt.get(10).get(9).allele(),gt.get(10).get(10).allele(),
                gt.get(10).get(11).allele()};
        return outputRule;
    }
    static int[] fromGenotypeToArrayU2r(final Genotype<IntegerGene> gt){
        int[] outputRule = new int[]{gt.get(0).get(0).allele(), gt.get(1).get(0).allele(),gt.get(2).get(0).allele(),
                gt.get(3).get(0).allele(),gt.get(4).get(0).allele(),gt.get(4).get(1).allele(),
                gt.get(5).get(0).allele(),gt.get(6).get(0).allele(),gt.get(7).get(0).allele(),
                gt.get(8).get(0).allele(),gt.get(9).get(0).allele(),gt.get(10).get(0).allele(),
                gt.get(10).get(1).allele(),gt.get(10).get(2).allele(),gt.get(10).get(3).allele(),
                gt.get(10).get(4).allele(),gt.get(10).get(5).allele(),gt.get(10).get(6).allele(),
                gt.get(10).get(7).allele(),gt.get(10).get(8).allele(),gt.get(10).get(9).allele(),
                gt.get(10).get(10).allele()};
        return outputRule;
    }
    static ArrayList<Double> performace(final Genotype<IntegerGene> gt){
        Double TP=0.0, TN=0.0, FP=0.0, FN=0.0;
        mapFound.clear();
        int n=0;
        for(Connection c: l) {
            n=0;
            if (gt.get(10).length() >= 13) {
                if ((compare(c.getDuration(), gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                        (compare(c.getProtocolType(), gt.get(1).get(0).allele(), EQUALS)) &&
                        (compare(c.getService(), gt.get(2).get(0).allele(), EQUALS)) &&
                        (compare(c.getFlag(), gt.get(3).get(0).allele(), EQUALS)) &&
                        (compare(c.getSrcBytes(), gt.get(4).get(0).allele(), gt.get(10).get(1).allele())) &&
                        (compare(c.getDstBytes(), gt.get(5).get(0).allele(), gt.get(10).get(2).allele())) &&
                        (compare(c.getLand(), gt.get(6).get(0).allele(), EQUALS)) &&
                        (compare(c.getWrongFragment(), gt.get(7).get(0).allele(), gt.get(10).get(3).allele())) &&
                        (compare(c.getUrgent(), gt.get(7).get(1).allele(), gt.get(10).get(4).allele())) &&
                        (compare(c.getCount(), gt.get(8).get(0).allele(), gt.get(10).get(5).allele())) &&
                        (compare(c.getSrvCount(), gt.get(8).get(1).allele(), gt.get(10).get(6).allele())) &&
                        (compare(c.getSerrorRate(), gt.get(9).get(0).allele(), gt.get(10).get(7).allele())) &&
                        (compare(c.getSrvSerrorRate(), gt.get(9).get(1).allele(), gt.get(10).get(8).allele())) &&
                        (compare(c.getRerrorRate(), gt.get(9).get(2).allele(), gt.get(10).get(9).allele())) &&
                        (compare(c.getSrvRerrorRate(), gt.get(9).get(3).allele(), gt.get(10).get(10).allele())) &&
                        (compare(c.getSameSrvRate(), gt.get(9).get(4).allele(), gt.get(10).get(11).allele())) &&
                        (compare(c.getDiffSrvRate(), gt.get(9).get(5).allele(), gt.get(10).get(12).allele())) &&
                        (compare(c.getSrvDiffHostRate(), gt.get(9).get(6).allele(), gt.get(10).get(13).allele()))) {

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }

            } else  if (gt.get(10).length() == 12){
                if((compare(c.getDuration(),gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                        (compare(c.getDstBytes(),gt.get(1).get(0).allele(), gt.get(10).get(1).allele())) &&
                        (compare(c.getLoggedIn(),gt.get(2).get(0).allele(), gt.get(10).get(2).allele())) &&
                        (compare(c.getSuAttempted(), gt.get(3).get(0).allele(), gt.get(10).get(3).allele())) &&
                        (compare(c.getNumShells(), gt.get(3).get(1).allele(), gt.get(10).get(4).allele())) &&
                        (compare(c.getNumRoot(),gt.get(4).get(0).allele(), gt.get(10).get(5).allele())) &&
                        (compare(c.getNumFilesCreations(), gt.get(5).get(0).allele(), gt.get(10).get(6).allele())) &&
                        (compare(c.getNumAccessFiles(),gt.get(6).get(0).allele(), gt.get(10).get(7).allele())) &&
                        (compare(c.getSrvDiffHostRate(),gt.get(7).get(0).allele(), gt.get(10).get(8).allele())) &&
                        (compare(c.getDstHostSrvDiffHostRate(),gt.get(7).get(1).allele(), gt.get(10).get(9).allele())) &&
                        (compare(c.getRerrorRate(),gt.get(7).get(2).allele(), gt.get(10).get(10).allele())) &&
                        (compare(c.getDstHostCount(),gt.get(8).get(0).allele(), gt.get(10).get(11).allele())) &&
                        (compare(c.getFlag(),gt.get(9).get(0).allele(), EQUALS))){

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }
            }
            else if(gt.get(10).length() == 11){
                if((compare(c.getDuration(),gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                        (compare(c.getSrcBytes(),gt.get(1).get(0).allele(), gt.get(10).get(1).allele())) &&
                        (compare(c.getDstBytes(),gt.get(2).get(0).allele(), gt.get(10).get(2).allele())) &&
                        (compare(c.getLoggedIn(),gt.get(3).get(0).allele(), gt.get(10).get(3).allele())) &&
                        (compare(c.getSuAttempted(), gt.get(4).get(0).allele(), gt.get(10).get(4).allele())) &&
                        (compare(c.getNumShells(), gt.get(4).get(1).allele(), gt.get(10).get(5).allele())) &&
                        (compare(c.getNumRoot(),gt.get(5).get(0).allele(), gt.get(10).get(6).allele())) &&
                        (compare(c.getNumFilesCreations(), gt.get(6).get(0).allele(), gt.get(10).get(7).allele())) &&
                        (compare(c.getNumAccessFiles(),gt.get(7).get(0).allele(), gt.get(10).get(8).allele())) &&
                        (compare(c.getSrvDiffHostRate(),gt.get(8).get(0).allele(), gt.get(10).get(9).allele())) &&
                        (compare(c.getDstHostSrvDiffHostRate(),gt.get(9).get(0).allele(), gt.get(10).get(10).allele()))
                ){

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }
            }
        }
       ArrayList<Double> results = new ArrayList<>();
        results.add(TP);
        results.add(TN);
        results.add(FP);
        results.add(FN);
        return results;
    }

    static ArrayList<Double> performaceValidation(final Genotype<IntegerGene> gt){
        Double TP=0.0, TN=0.0, FP=0.0, FN=0.0;
        mapFound.clear();
        int n=0;
        for(Connection c: lValidation) {
            n=0;
            if (gt.get(10).length() >= 13) {
                if ((compare(c.getDuration(), gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                        (compare(c.getProtocolType(), gt.get(1).get(0).allele(), EQUALS)) &&
                        (compare(c.getService(), gt.get(2).get(0).allele(), EQUALS)) &&
                        (compare(c.getFlag(), gt.get(3).get(0).allele(), EQUALS)) &&
                        (compare(c.getSrcBytes(), gt.get(4).get(0).allele(), gt.get(10).get(1).allele())) &&
                        (compare(c.getDstBytes(), gt.get(5).get(0).allele(), gt.get(10).get(2).allele())) &&
                        (compare(c.getLand(), gt.get(6).get(0).allele(), EQUALS)) &&
                        (compare(c.getWrongFragment(), gt.get(7).get(0).allele(), gt.get(10).get(3).allele())) &&
                        (compare(c.getUrgent(), gt.get(7).get(1).allele(), gt.get(10).get(4).allele())) &&
                        (compare(c.getCount(), gt.get(8).get(0).allele(), gt.get(10).get(5).allele())) &&
                        (compare(c.getSrvCount(), gt.get(8).get(1).allele(), gt.get(10).get(6).allele())) &&
                        (compare(c.getSerrorRate(), gt.get(9).get(0).allele(), gt.get(10).get(7).allele())) &&
                        (compare(c.getSrvSerrorRate(), gt.get(9).get(1).allele(), gt.get(10).get(8).allele())) &&
                        (compare(c.getRerrorRate(), gt.get(9).get(2).allele(), gt.get(10).get(9).allele())) &&
                        (compare(c.getSrvRerrorRate(), gt.get(9).get(3).allele(), gt.get(10).get(10).allele())) &&
                        (compare(c.getSameSrvRate(), gt.get(9).get(4).allele(), gt.get(10).get(11).allele())) &&
                        (compare(c.getDiffSrvRate(), gt.get(9).get(5).allele(), gt.get(10).get(12).allele())) &&
                        (compare(c.getSrvDiffHostRate(), gt.get(9).get(6).allele(), gt.get(10).get(13).allele()))) {

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }

            } else  if (gt.get(10).length() == 12){
                if((compare(c.getDuration(),gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                        (compare(c.getDstBytes(),gt.get(1).get(0).allele(), gt.get(10).get(1).allele())) &&
                        (compare(c.getLoggedIn(),gt.get(2).get(0).allele(), gt.get(10).get(2).allele())) &&
                        (compare(c.getSuAttempted(), gt.get(3).get(0).allele(), gt.get(10).get(3).allele())) &&
                        (compare(c.getNumShells(), gt.get(3).get(1).allele(), gt.get(10).get(4).allele())) &&
                        (compare(c.getNumRoot(),gt.get(4).get(0).allele(), gt.get(10).get(5).allele())) &&
                        (compare(c.getNumFilesCreations(), gt.get(5).get(0).allele(), gt.get(10).get(6).allele())) &&
                        (compare(c.getNumAccessFiles(),gt.get(6).get(0).allele(), gt.get(10).get(7).allele())) &&
                        (compare(c.getSrvDiffHostRate(),gt.get(7).get(0).allele(), gt.get(10).get(8).allele())) &&
                        (compare(c.getDstHostSrvDiffHostRate(),gt.get(7).get(1).allele(), gt.get(10).get(9).allele())) &&
                        (compare(c.getRerrorRate(),gt.get(7).get(2).allele(), gt.get(10).get(10).allele())) &&
                        (compare(c.getDstHostCount(),gt.get(8).get(0).allele(), gt.get(10).get(11).allele())) &&
                        (compare(c.getFlag(),gt.get(9).get(0).allele(), EQUALS))){

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }
            }
            else if(gt.get(10).length() == 11){
                if((compare(c.getDuration(),gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                        (compare(c.getSrcBytes(),gt.get(1).get(0).allele(), gt.get(10).get(1).allele())) &&
                        (compare(c.getDstBytes(),gt.get(2).get(0).allele(), gt.get(10).get(2).allele())) &&
                        (compare(c.getLoggedIn(),gt.get(3).get(0).allele(), gt.get(10).get(3).allele())) &&
                        (compare(c.getSuAttempted(), gt.get(4).get(0).allele(), gt.get(10).get(4).allele())) &&
                        (compare(c.getNumShells(), gt.get(4).get(1).allele(), gt.get(10).get(5).allele())) &&
                        (compare(c.getNumRoot(),gt.get(5).get(0).allele(), gt.get(10).get(6).allele())) &&
                        (compare(c.getNumFilesCreations(), gt.get(6).get(0).allele(), gt.get(10).get(7).allele())) &&
                        (compare(c.getNumAccessFiles(),gt.get(7).get(0).allele(), gt.get(10).get(8).allele())) &&
                        (compare(c.getSrvDiffHostRate(),gt.get(8).get(0).allele(), gt.get(10).get(9).allele())) &&
                        (compare(c.getDstHostSrvDiffHostRate(),gt.get(9).get(0).allele(), gt.get(10).get(10).allele()))
                ){

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }
            }
        }
        ArrayList<Double> results = new ArrayList<>();
        results.add(TP);
        results.add(TN);
        results.add(FP);
        results.add(FN);
        return results;
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


    static ArrayList<Double> performaceArray(int[] gt){
        Double TP=0.0, TN=0.0, FP=0.0, FN=0.0;
        mapFound.clear();
        int n=0;
        for(Connection c: l) {
            n=0;
            if (gt.length>30) {
                if ((compare(c.getDuration(), gt[0], gt[18])) &&
                        (compare(c.getProtocolType(), gt[19], EQUALS)) &&
                        (compare(c.getService(), gt[2], EQUALS)) &&
                        (compare(c.getFlag(), gt[3], EQUALS)) &&
                        (compare(c.getSrcBytes(), gt[4], gt[20])) &&
                        (compare(c.getDstBytes(), gt[5], gt[21])) &&
                        (compare(c.getLand(), gt[6], EQUALS)) &&
                        (compare(c.getWrongFragment(), gt[7], gt[22])) &&
                        (compare(c.getUrgent(), gt[8], gt[23])) &&
                        (compare(c.getCount(), gt[9], gt[24])) &&
                        (compare(c.getSrvCount(), gt[10], gt[25])) &&
                        (compare(c.getSerrorRate(), gt[11], gt[26])) &&
                        (compare(c.getSrvSerrorRate(), gt[12], gt[27])) &&
                        (compare(c.getRerrorRate(), gt[13], gt[28])) &&
                        (compare(c.getSrvRerrorRate(), gt[14], gt[29])) &&
                        (compare(c.getSameSrvRate(), gt[15], gt[30])) &&
                        (compare(c.getDiffSrvRate(), gt[16], gt[31])) &&
                        (compare(c.getSrvDiffHostRate(), gt[17], gt[32]))) {

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }

            } else  if (gt.length==25){
                if((compare(c.getDuration(),gt[0], gt[13])) &&
                        (compare(c.getDstBytes(),gt[1], gt[14])) &&
                        (compare(c.getLoggedIn(),gt[2], gt[15])) &&
                        (compare(c.getSuAttempted(), gt[3], gt[16])) &&
                        (compare(c.getNumShells(), gt[4], gt[17])) &&
                        (compare(c.getNumRoot(),gt[5], gt[18])) &&
                        (compare(c.getNumFilesCreations(), gt[6], gt[19])) &&
                        (compare(c.getNumAccessFiles(),gt[7], gt[20])) &&
                        (compare(c.getSrvDiffHostRate(),gt[8], gt[21])) &&
                        (compare(c.getDstHostSrvDiffHostRate(),gt[9], gt[22])) &&
                        (compare(c.getRerrorRate(),gt[10], gt[23])) &&
                        (compare(c.getDstHostCount(),gt[11], gt[24])) &&
                        (compare(c.getFlag(),gt[12], EQUALS))){

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }
            }
            else{
                if((compare(c.getDuration(),gt[0], gt[11])) &&
                        (compare(c.getSrcBytes(),gt[1], gt[12])) &&
                        (compare(c.getDstBytes(),gt[2], gt[13])) &&
                        (compare(c.getLoggedIn(),gt[3], gt[14])) &&
                        (compare(c.getSuAttempted(), gt[4], gt[15])) &&
                        (compare(c.getNumShells(), gt[5], gt[16])) &&
                        (compare(c.getNumRoot(),gt[6], gt[17])) &&
                        (compare(c.getNumFilesCreations(), gt[7], gt[18])) &&
                        (compare(c.getNumAccessFiles(),gt[8], gt[19])) &&
                        (compare(c.getSrvDiffHostRate(),gt[9], gt[20])) &&
                        (compare(c.getDstHostSrvDiffHostRate(),gt[10], gt[21]))
                ){

                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        TP++;
                        if (mapFound.containsKey(c.getLabel()))
                            n = mapFound.get(c.getLabel());
                        mapFound.put(c.getLabel(), n + 1);
                    } else {
                        FP++;
                    }
                } else {
                    if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                        FN++;
                    } else {
                        TN++;
                    }
                }
            }
        }
        ArrayList<Double> results = new ArrayList<>();
        results.add(TP);
        results.add(TN);
        results.add(FP);
        results.add(FN);
        return results;
    }

    static Double fitness(final Genotype<IntegerGene> gt){
        Double a=0.0, ab=0.0;
        int n=0;
        mapFoundTmp.clear();
        for(Connection c: l){
            if((compare(c.getDuration(),gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                    (compare(c.getProtocolType(),gt.get(1).get(0).allele(), EQUALS)) &&
                    (compare(c.getService(),gt.get(2).get(0).allele(), EQUALS)) &&
                    (compare(c.getFlag(), gt.get(3).get(0).allele(), EQUALS)) &&
                    (compare(c.getSrcBytes(), gt.get(4).get(0).allele(), gt.get(10).get(1).allele())) &&
                    (compare(c.getDstBytes(),gt.get(5).get(0).allele(), gt.get(10).get(2).allele())) &&
                    (compare(c.getLand(), gt.get(6).get(0).allele(), EQUALS)) &&
                    (compare(c.getWrongFragment(),gt.get(7).get(0).allele(), gt.get(10).get(3).allele())) &&
                    (compare(c.getUrgent(),gt.get(7).get(1).allele(), gt.get(10).get(4).allele())) &&
                    (compare(c.getCount(),gt.get(8).get(0).allele(), gt.get(10).get(5).allele())) &&
                    (compare(c.getSrvCount(),gt.get(8).get(1).allele(), gt.get(10).get(6).allele())) &&
                    (compare(c.getSerrorRate(),gt.get(9).get(0).allele(), gt.get(10).get(7).allele())) &&
                    (compare(c.getSrvSerrorRate(),gt.get(9).get(1).allele(), gt.get(10).get(8).allele())) &&
                    (compare(c.getRerrorRate(),gt.get(9).get(2).allele(), gt.get(10).get(9).allele())) &&
                    (compare(c.getSrvRerrorRate(),gt.get(9).get(3).allele(), gt.get(10).get(10).allele())) &&
                    (compare(c.getSameSrvRate(),gt.get(9).get(4).allele(), gt.get(10).get(11).allele())) &&
                    (compare(c.getDiffSrvRate(),gt.get(9).get(5).allele(), gt.get(10).get(12).allele())) &&
                    (compare(c.getSrvDiffHostRate(),gt.get(9).get(6).allele(), gt.get(10).get(13).allele()))) {

                if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                    ab = ab + 1;
                    n=0;

                }else{
                    a = a + 1;}
            }
        }
        Double value =  (ab/A)-(a/B);
        if(value.isNaN())
            return 0.0;
        if(value>bestFitness){
            bestFitness=value;
        }
        return value;
    }
    static Double fitnessProbe(final Genotype<IntegerGene> gt){
        Double a=0.0, ab=0.0;
        int n=0;
        mapFoundTmp.clear();
        for(Connection c: l){
            if((compare(c.getDuration(),gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                    (compare(c.getDstBytes(),gt.get(1).get(0).allele(), gt.get(10).get(1).allele())) &&
                    (compare(c.getLoggedIn(),gt.get(2).get(0).allele(), gt.get(10).get(2).allele())) &&
                    (compare(c.getSuAttempted(), gt.get(3).get(0).allele(), gt.get(10).get(3).allele())) &&
                    (compare(c.getNumShells(), gt.get(3).get(1).allele(), gt.get(10).get(4).allele())) &&
                    (compare(c.getNumRoot(),gt.get(4).get(0).allele(), gt.get(10).get(5).allele())) &&
                    (compare(c.getNumFilesCreations(), gt.get(5).get(0).allele(), gt.get(10).get(6).allele())) &&
                    (compare(c.getNumAccessFiles(),gt.get(6).get(0).allele(), gt.get(10).get(7).allele())) &&
                    (compare(c.getSrvDiffHostRate(),gt.get(7).get(0).allele(), gt.get(10).get(8).allele())) &&
                    (compare(c.getDstHostSrvDiffHostRate(),gt.get(7).get(1).allele(), gt.get(10).get(9).allele())) &&
                    (compare(c.getRerrorRate(),gt.get(7).get(2).allele(), gt.get(10).get(10).allele())) &&
                    (compare(c.getDstHostCount(),gt.get(8).get(0).allele(), gt.get(10).get(11).allele())) &&
                    (compare(c.getFlag(),gt.get(9).get(0).allele(), EQUALS))){

                if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                    ab = ab + 1;
                    n=0;

                }else{
                    a = a + 1;}
            }
        }
        Double value =  (ab/A)-(a/B);
        if(value.isNaN())
            return 0.0;
        if(value>bestFitness){
            bestFitness=value;
        }
        return value;
    }
    static Double fitnessU2r(final Genotype<IntegerGene> gt){
        Double a=0.0, ab=0.0;
        int n=0;
        mapFoundTmp.clear();
        for(Connection c: l){
            if((compare(c.getDuration(),gt.get(0).get(0).allele(), gt.get(10).get(0).allele())) &&
                    (compare(c.getSrcBytes(),gt.get(1).get(0).allele(), gt.get(10).get(1).allele())) &&
                    (compare(c.getDstBytes(),gt.get(2).get(0).allele(), gt.get(10).get(2).allele())) &&
                    (compare(c.getLoggedIn(),gt.get(3).get(0).allele(), gt.get(10).get(3).allele())) &&
                    (compare(c.getSuAttempted(), gt.get(4).get(0).allele(), gt.get(10).get(4).allele())) &&
                    (compare(c.getNumShells(), gt.get(4).get(1).allele(), gt.get(10).get(5).allele())) &&
                    (compare(c.getNumRoot(),gt.get(5).get(0).allele(), gt.get(10).get(6).allele())) &&
                    (compare(c.getNumFilesCreations(), gt.get(6).get(0).allele(), gt.get(10).get(7).allele())) &&
                    (compare(c.getNumAccessFiles(),gt.get(7).get(0).allele(), gt.get(10).get(8).allele())) &&
                    (compare(c.getSrvDiffHostRate(),gt.get(8).get(0).allele(), gt.get(10).get(9).allele())) &&
                    (compare(c.getDstHostSrvDiffHostRate(),gt.get(9).get(0).allele(), gt.get(10).get(10).allele()))
                    ){

                if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                    ab = ab + 1;
                    n=0;

                }else{
                    a = a + 1;}
            }
        }
        Double value =  (ab/A)-(a/B);
        if(value.isNaN())
            return 0.0;
        if(value>bestFitness){
            bestFitness=value;
        }
        return value;
    }

    public static void run(int population, int generations, int nRule){

        l=missingAttacksList(l, bestRules);
        System.out.println("Size l: "+l.size());
        System.out.println("REGOLA "+nRule+" (DOS):");
        A=B=0.0;
        mapAttacks2.clear();
        int n=0;
        for(Connection c: l){
            String label= c.getLabel();
            if(label.equalsIgnoreCase("normal"))
                B++;
            else {A++;
                n=0;
                if(mapAttacks2.containsKey(label)){
                    n=mapAttacks2.get(label);
                }
                mapAttacks2.put(label, n+1);
            }
        }
        System.out.println("Number of attacks: "+A+"\nNumber of normal connections: "+B);
        System.out.println("Attacks: "+mapAttacks2.toString());
        final Factory<Genotype<IntegerGene>> GTF = Genotype.of(
                IntegerChromosome.of(0, 58329),
                IntegerChromosome.of(1, 3),
                IntegerChromosome.of(1,66),
                IntegerChromosome.of(1, 11),
                IntegerChromosome.of(0,999),
                IntegerChromosome.of(0,9999),
                IntegerChromosome.of(0,1),
                IntegerChromosome.of(0,3,2),
                IntegerChromosome.of(0, 99, 2),
                IntegerChromosome.of(0, 100, 7),
                IntegerChromosome.of(1, 2, 14)
        );

        final Engine<IntegerGene, Double> engine;
        engine = Engine.builder(
                        RunnerConfig100p::fitness,
                        GTF).populationSize(population)
                .selector(new EliteSelector<>())
                .optimize(Optimize.MAXIMUM)
                .alterers(
                        new Mutator<>(0.1),
                        new SinglePointCrossover<>(0.9)
                ).build();

        final EvolutionStatistics<Double, ?>
                statistics= EvolutionStatistics.ofNumber();

        final Phenotype<IntegerGene, Double> best= engine.stream()
                .limit(generations)
                .peek(statistics)
                .collect(toBestPhenotype());

        System.out.println(statistics);
        System.out.println(best);
        performace(best.genotype());
        bestRules.add(fromGenotypeToArrayDos(best.genotype()));
        ArrayList<Double> results= performanceRuleSet(bestRules, (ArrayList<Connection>) l);

        System.out.println("Attacks found: "+mapFound.toString());
        System.out.println("Best fitness: "+bestFitness);

        Double TP= results.get(0);
        Double TN= results.get(1);
        Double FP= results.get(2);
        Double FN= results.get(3);
        Double accuracy= ((TP+TN)/(TP+TN+FP+FN));
        Double detectionRate= (TP)/(FN+TP);
        Double falseAlarms= (FP)/(TN+FP);
        System.out.println("Training and Validation:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy+"%");
        System.out.println("Detection Rate: "+detectionRate+"%");
        System.out.println("False Alarms: "+falseAlarms+"%");

    }

    public static void runDiversiDataset(int population, int generations, int nRule) throws IOException {
        l=DatasetLoader.parse(new File("src/main/resources/kddcup99_csv.csv"));
        createTrainingAndValidationSetsNoSave();
        l=missingAttacksList(l, bestRules);
        System.out.println("Size l: "+l.size());
        System.out.println("REGOLA "+nRule+":");
        A=B=0.0;
        mapAttacks.clear();
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
        System.out.println("Number of attacks: "+A+"\nNumber of normal connections: "+B);
        System.out.println("Attacks: "+mapAttacks.toString());
        final Factory<Genotype<IntegerGene>> GTF = Genotype.of(
                IntegerChromosome.of(0, 58329),
                IntegerChromosome.of(1, 3),
                IntegerChromosome.of(1,66),
                IntegerChromosome.of(1, 11),
                IntegerChromosome.of(0,999),
                IntegerChromosome.of(0,9999),
                IntegerChromosome.of(0,1),
                IntegerChromosome.of(0,3,2),
                IntegerChromosome.of(0, 99, 2),
                IntegerChromosome.of(0, 100, 7),
                IntegerChromosome.of(1, 2, 14)
        );

        final Engine<IntegerGene, Double> engine;
        engine = Engine.builder(
                        RunnerConfig100p::fitness,
                        GTF).populationSize(population)
                .selector(new EliteSelector<>())
                .optimize(Optimize.MAXIMUM)
                .alterers(
                        new Mutator<>(0.1),
                        new SinglePointCrossover<>(0.9)
                ).build();

        final EvolutionStatistics<Double, ?>
                statistics= EvolutionStatistics.ofNumber();

        final Phenotype<IntegerGene, Double> best= engine.stream()
                .limit(generations)
                .peek(statistics)
                .collect(toBestPhenotype());

        System.out.println(statistics);
        System.out.println(best);
        performace(best.genotype());
        bestRules.add(fromGenotypeToArrayDos(best.genotype()));
        ArrayList<Double> results= performanceRuleSet(bestRules, (ArrayList<Connection>) l);

        System.out.println("Attacks found: "+mapFound.toString());
        System.out.println("Best fitness: "+bestFitness);

        Double TP= results.get(0);
        Double TN= results.get(1);
        Double FP= results.get(2);
        Double FN= results.get(3);
        Double accuracy= ((TP+TN)/(TP+TN+FP+FN));
        Double detectionRate= (TP)/(FN+TP);
        Double falseAlarms= (FP)/(TN+FP);
        System.out.println("Training and Validation:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy+"%");
        System.out.println("Detection Rate: "+detectionRate+"%");
        System.out.println("False Alarms: "+falseAlarms+"%");

    }

    public static void runProbe(int population, int generations, int nRule){

        l=missingAttacksList(l, bestRules);
        System.out.println("Size l: "+l.size());
        System.out.println("REGOLA "+nRule+" (PROBE):");
        A=B=0.0;
        mapAttacks2.clear();
        int n=0;
        for(Connection c: l){
            String label= c.getLabel();
            if(label.equalsIgnoreCase("normal"))
                B++;
            else {A++;
                n=0;
                if(mapAttacks2.containsKey(label)){
                    n=mapAttacks2.get(label);
                }
                mapAttacks2.put(label, n+1);
            }
        }
        System.out.println("Number of attacks: "+A+"\nNumber of normal connections: "+B);
        System.out.println("Attacks: "+mapAttacks2.toString());

//feature più rilevanti per la classe "normal" e per gli attacchi di tipo "probe"
        final Factory<Genotype<IntegerGene>> GTF = Genotype.of(
                IntegerChromosome.of(0, 58329),//duration
                IntegerChromosome.of(0,9999),//dstBytes
                IntegerChromosome.of(0,1),//loggedIn
                IntegerChromosome.of(0,2, 2), //suAttempted e numShells
                IntegerChromosome.of(0, 993), //numRoot
                IntegerChromosome.of(0, 28), //numFilesCreations
                IntegerChromosome.of(0, 8), //numAccessFiles
                IntegerChromosome.of(0, 100, 3), //srvDiffHostRate e dstHostSrvDiffHostRate e rerrorRate
                IntegerChromosome.of(0, 260), //dstHostCount
                IntegerChromosome.of(1, 11), //flag (map)
                IntegerChromosome.of(1, 2, 12) //segni diseguaglianze
        );

        final Engine<IntegerGene, Double> engine;
        engine = Engine.builder(
                        RunnerConfig100p::fitnessProbe,
                        GTF).populationSize(population)
                .selector(new EliteSelector<>())
                .optimize(Optimize.MAXIMUM)
                .alterers(
                        new Mutator<>(0.1),
                        new SinglePointCrossover<>(0.9)
                ).build();

        final EvolutionStatistics<Double, ?>
                statistics= EvolutionStatistics.ofNumber();

        final Phenotype<IntegerGene, Double> best= engine.stream()
                .limit(generations)
                .peek(statistics)
                .collect(toBestPhenotype());

        System.out.println(statistics);
        System.out.println(best);
        performace(best.genotype());
        bestRules.add(fromGenotypeToArrayProbe(best.genotype()));
        ArrayList<Double> results= performanceRuleSet(bestRules, (ArrayList<Connection>) l);

        System.out.println("Attacks found: "+mapFound.toString());
        System.out.println("Best fitness: "+bestFitness);

        Double TP= results.get(0);
        Double TN= results.get(1);
        Double FP= results.get(2);
        Double FN= results.get(3);
        Double accuracy= ((TP+TN)/(TP+TN+FP+FN));
        Double detectionRate= (TP)/(FN+TP);
        Double falseAlarms= (FP)/(TN+FP);
        System.out.println("Training and Validation:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy+"%");
        System.out.println("Detection Rate: "+detectionRate+"%");
        System.out.println("False Alarms: "+falseAlarms+"%");
    }

    public static void runU2r(int population, int generations, int nRule){

        l=missingAttacksList(l, bestRules);
        System.out.println("Size l: "+l.size());
        System.out.println("REGOLA "+nRule+" (U2R):");
        A=B=0.0;
        mapAttacks2.clear();
        int n=0;
        for(Connection c: l){
            String label= c.getLabel();
            if(label.equalsIgnoreCase("normal"))
                B++;
            else {A++;
                n=0;
                if(mapAttacks2.containsKey(label)){
                    n=mapAttacks2.get(label);
                }
                mapAttacks2.put(label, n+1);
            }
        }
        System.out.println("Number of attacks: "+A+"\nNumber of normal connections: "+B);
        System.out.println("Attacks: "+mapAttacks2.toString());

//feature più rilevanti per la classe "normal" e per gli attacchi di tipo "U2r"
        final Factory<Genotype<IntegerGene>> GTF = Genotype.of(
                IntegerChromosome.of(0, 58329),//duration (1)
                IntegerChromosome.of(0, 999),//srcBytes (5)
                IntegerChromosome.of(0,9999),//dstBytes (6)
                IntegerChromosome.of(0,1),//loggedIn (12)
                IntegerChromosome.of(0,2, 2), //suAttempted (15) e numShells (18)
                IntegerChromosome.of(0, 993), //numRoot (16)
                IntegerChromosome.of(0, 28), //numFilesCreations (17)
                IntegerChromosome.of(0, 8), //numAccessFiles (19)
                IntegerChromosome.of(0, 100), //srvDiffHostRate (31)
                IntegerChromosome.of(0, 260), //dstHostCount (32)
                IntegerChromosome.of(1, 2, 11) //segni diseguaglianze
        );

        final Engine<IntegerGene, Double> engine;
        engine = Engine.builder(
                        RunnerConfig100p::fitnessU2r,
                        GTF).populationSize(population)
                .selector(new EliteSelector<>())
                .optimize(Optimize.MAXIMUM)
                .alterers(
                        new Mutator<>(0.1),
                        new SinglePointCrossover<>(0.9)
                ).build();

        final EvolutionStatistics<Double, ?>
                statistics= EvolutionStatistics.ofNumber();

        final Phenotype<IntegerGene, Double> best= engine.stream()
                .limit(generations)
                .peek(statistics)
                .collect(toBestPhenotype());

        System.out.println(statistics);
        System.out.println(best);
        performace(best.genotype());
        bestRules.add(fromGenotypeToArrayU2r(best.genotype()));
        ArrayList<Double> results= performanceRuleSet(bestRules, (ArrayList<Connection>) l);

        System.out.println("Attacks found: "+mapFound.toString());
        System.out.println("Best fitness: "+bestFitness);

        Double TP= results.get(0);
        Double TN= results.get(1);
        Double FP= results.get(2);
        Double FN= results.get(3);
        Double accuracy= ((TP+TN)/(TP+TN+FP+FN));
        Double detectionRate= (TP)/(FN+TP);
        Double falseAlarms= (FP)/(TN+FP);
        System.out.println("Training and Validation:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy+"%");
        System.out.println("Detection Rate: "+detectionRate+"%");
        System.out.println("False Alarms: "+falseAlarms+"%");

    }

    public static void printStatisticsTraining(){
        System.out.println("TRAINING: ");
        ArrayList<Double> results= performanceRuleSet(bestRules, (ArrayList<Connection>) lCopy);
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
        ArrayList<Connection> missingAttacksList= (ArrayList<Connection>) missingAttacksList(lCopy, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //Probe
        ArrayList<Connection> lProbe=filterProbe((ArrayList<Connection>) lCopy);
        results= performanceRuleSet(bestRules, lProbe);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Probe: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksProbe = findMissingAttacks(mapAttacks, mapFound);
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
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //Dos
        ArrayList<Connection> lDos=filterDos((ArrayList<Connection>) lCopy);
        results= performanceRuleSet(bestRules, lDos);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Dos: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksDos = findMissingAttacks(mapAttacks, mapFound);
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
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lDos, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //U2R
        ArrayList<Connection> lU2r=filterU2r((ArrayList<Connection>) lCopy);
        results= performanceRuleSet(bestRules, lU2r);
        System.out.println("////////////");
        System.out.println("Attacchi trovati U2r: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksU2r = findMissingAttacks(mapAttacks, mapFound);
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
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lU2r, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //R2L
        ArrayList<Connection> lR2l=filterR2l((ArrayList<Connection>) lCopy);
        results= performanceRuleSet(bestRules, lR2l);
        System.out.println("////////////");
        System.out.println("Attacchi trovati R2l: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksR2l = findMissingAttacks(mapAttacks, mapFound);
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
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lR2l, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());
        plotStatistics(bestRules, (ArrayList<Connection>) lCopy);
        plotConfusionMatrixCSV(bestRules, (ArrayList<Connection>) lCopy);
    }

    public static void printStatisticsValidation(){
        System.out.println("VALIDATION: ");
        ArrayList<Double> results= performanceRuleSet(bestRules, (ArrayList<Connection>) lValidation);
        System.out.println("Attacchi trovati: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacks = findMissingAttacks(mapAttacksV, mapFound);
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
        HashMap<String, Double> attacksPercentage= findAttackPercentages(mapAttacksV, mapFound);
        System.out.println("Percentuali tipi di attacchi trovati:\n"+attacksPercentage.toString());
        System.out.println("Numero di regole concatenate: "+bestRules.size());
        ArrayList<Connection> missingAttacksList= (ArrayList<Connection>) missingAttacksList(lValidation, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //Probe
        ArrayList<Connection> lProbe=filterProbe((ArrayList<Connection>) lValidation);
        results= performanceRuleSet(bestRules, lProbe);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Probe: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksProbe = findMissingAttacks(mapAttacksV, mapFound);
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
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //Dos
        ArrayList<Connection> lDos=filterDos((ArrayList<Connection>) lValidation);
        results= performanceRuleSet(bestRules, lDos);
        System.out.println("////////////");
        System.out.println("Attacchi trovati Dos: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksDos = findMissingAttacks(mapAttacksV, mapFound);
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
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //U2R
        ArrayList<Connection> lU2r=filterU2r((ArrayList<Connection>) lValidation);
        results= performanceRuleSet(bestRules, lU2r);
        System.out.println("////////////");
        System.out.println("Attacchi trovati U2r: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksU2r = findMissingAttacks(mapAttacksV, mapFound);
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
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());

        //R2L
        ArrayList<Connection> lR2l=filterR2l((ArrayList<Connection>) lValidation);
        results= performanceRuleSet(bestRules, lR2l);
        System.out.println("////////////");
        System.out.println("Attacchi trovati R2l: "+mapFound.toString());
        HashMap<String, Integer> mapMissingAttacksR2l = findMissingAttacks(mapAttacksV, mapFound);
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
        missingAttacksList= (ArrayList<Connection>) missingAttacksList(lProbe, bestRules);
        System.out.println("Numero attacchi mancanti: "+missingAttacksList.size());
        plotStatistics(bestRules, (ArrayList<Connection>) lValidation);
        plotConfusionMatrixCSV(bestRules, (ArrayList<Connection>) lValidation);
    }
    public static void basicRun(List<Connection> l, int population, int generations){

        A=B=0.0;
        mapAttacks.clear();
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
        System.out.println(l.get(0));
        System.out.println("Number of attacks: "+A+"\nNumber of normal connections: "+B);
        System.out.println("Attacks: "+mapAttacks.toString());
        final Factory<Genotype<IntegerGene>> GTF = Genotype.of(
                IntegerChromosome.of(0, 58329),//duration (1)
                IntegerChromosome.of(1, 3),//protocolType (2)
                IntegerChromosome.of(1,66),//service (3)
                IntegerChromosome.of(1, 11),//flag (4)
                IntegerChromosome.of(0,999),//srcBytes (5)
                IntegerChromosome.of(0,9999),//dstBytes (6)
                IntegerChromosome.of(0,1),//land (7)
                IntegerChromosome.of(0,3,2),//wrongFragment (8) e urgent (9)
                IntegerChromosome.of(0, 99, 2),//count (23) e srvCount (24)
                IntegerChromosome.of(0, 100, 7),//serrorRate (25), srvSerrorRate (26), rerrorRate (27),
                // srvRerrorRate (28), sameSrvRate (29), diffSrvRate (30) e srvDiffHostRate (31)
                IntegerChromosome.of(1, 2, 14)//segni diseguaglianze
        );

        final Engine<IntegerGene, Double> engine;
        engine = Engine.builder(
                        RunnerConfig100p::fitness,
                        GTF).populationSize(population)
                .selector(new EliteSelector<>())
                .optimize(Optimize.MAXIMUM)
                .alterers(
                        new Mutator<>(0.1),
                        new SinglePointCrossover<>(0.9)
                ).build();

        final EvolutionStatistics<Double, ?>
                statistics= EvolutionStatistics.ofNumber();

        final Phenotype<IntegerGene, Double> best= engine.stream()
                .limit(generations)
                .peek(statistics)
                .collect(toBestPhenotype());

        System.out.println(statistics);
        System.out.println(best);
        performace(best.genotype());
        System.out.println("Attacks found: "+mapFound.toString());
        System.out.println("Best fitness: "+bestFitness);
        ArrayList<Double> results= performace(best.genotype());
        Double TP= results.get(0);
        Double TN= results.get(1);
        Double FP= results.get(2);
        Double FN= results.get(3);
        Double accuracy= ((TP+TN)/(TP+TN+FP+FN));
        Double detectionRate= (TP)/(FN+TP);
        Double falseAlarms= (FP)/(TN+FP);
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy+"%");
        System.out.println("Detection Rate: "+detectionRate+"%");
        System.out.println("False Alarms: "+falseAlarms+"%");
    }
    public static void main(String[] args) throws IOException {
        l=DatasetLoader.parse(new File("src/main/resources/kddcup99_csv.csv"));
//        createTrainingAndValidationSetsNoSave();
        A=B=0.0;
        mapAttacks.clear();
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

        lCopy= (List<Connection>) new ArrayList<>(l).clone();

        System.out.println(l.size());

        System.out.println(l.get(0));
for(int i=1; i<=10; i++){
    runProbe(1000,1000, i);}

for(int i=11; i<=14; i++){
    run(1000,1000, i);}

for(int i=15; i<=17; i++){
    runU2r(1000,1000, i);}
printStatisticsTraining();
for(int[] e: bestRules)
    System.out.println(Arrays.toString(e));
    }
}
