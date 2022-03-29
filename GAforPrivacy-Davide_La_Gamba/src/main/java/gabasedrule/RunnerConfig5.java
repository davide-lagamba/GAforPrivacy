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

import static gabasedrule.Verifier.missingAttacksList;
import static io.jenetics.engine.EvolutionResult.toBestPhenotype;
import static io.jenetics.engine.Limits.byExecutionTime;

public class RunnerConfig5 {

    public static final Integer EQUALS=3;
    public static final Integer LESSER=1;
    public static final Integer GREATER=2;
    public static Double A;
    public static Double At;
    public static Double B;
    public static Double Bt;
    private static HashMap<String, Integer> mapAttacks = new HashMap<>();
    private static HashMap<String, Integer> mapAttacks2 = new HashMap<>();
    private static HashMap<String, Integer> mapFound = new HashMap<>();
    private static HashMap<String, Integer> mapFoundTmp = new HashMap<>();
    private static Double bestFitness=0.0;

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

    private static List<Connection> l;
    private static List<Connection> lTotale;
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

            } else {
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
    public static void run(List<Connection> l, int population, int generations){

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
                        RunnerConfig5::fitness,
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

    public static void runProbe(List<Connection> l, int population, int generations){
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
                        RunnerConfig5::fitnessProbe,
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
        int[] bestDosNoNeptune= new int[]{4460,3,10,1,243,9956,0,0,0,1,0,33,31,15,13,78,13,100,1,2,1,2,2,2,2,1,1,1,1,2,1,1};
        int[] bestDosOnlyNeptune= new int[]{23461,1,12,5,494,4581,0,1,0,0,45,46,42,75,72,100,100,16,1,1,1,1,2,2,1,2,2,1,1,1,1,1}; //poco utile
        int[] bestNoFilter= new int[]{44141,1,12,5,995,7680,0,2,0,0,28,2,41,96,75,0,100,9,1,1,1,1,1,2,1,2,2,1,1,2,1,1};
        int[] bestNoDos = new int[]{47494,1,11,3,189,8016,0,1,0,3,81,55,72,38,23,0,100,29,1,1,1,1,2,2,1,1,1,2,2,2,1,1};
        int[] bestProbe = new int[]{44907,1,11,3,925,3358,0,2,3,8,44,76,48,7,28,0,100,0,1,1,1,1,1,2,1,1,1,2,2,2,1,1}; //poco utile
        int[] bestProbeNoPortsweep = new int[]{36830,1,11,3,402,9571,0,0,0,25,73,99,5,41,57,36,53,63,1,1,1,2,2,2,1,1,1,2,2,1,2,1};//poco utile
        int[] bestRuleMissingNeptunes= new int[]{32065,1,12,3,689,7717,0,2,3,0,40,98,75,30,95,100,0,39,1,1,1,1,1,2,1,1,1,2,2,1,2,1};
        int[] bestRuleMissingTeardropAndIpSweep = new int[]{43302,3,8,1,23,589,0,3,2,0,1,100,86,0,0,0,100,100,1,1,1,1,1,2,2,1,1,2,1,2,1,1};
        ArrayList<int[]> bestRules= new ArrayList<>();
        bestRules.add(bestDosNoNeptune);
        bestRules.add(bestNoFilter);
        bestRules.add(bestNoDos);
        bestRules.add(bestRuleMissingNeptunes);
        int[] bestRuleMissingPortsweep = new int[]{56520,1,12,8,253,1545,0,1,2,0,71,0,96,0,0,0,100,90,1,1,1,1,1,2,1,2,1,2,2,2,1,1};
        bestRules.add(bestRuleMissingPortsweep);

        bestRules.add(bestRuleMissingTeardropAndIpSweep);
        int[] bestRuleMoreMissingPortsweep = new int[]{37345,1,11,8,248,1481,0,3,2,58,52,32,14,53,61,91,15,54,1,1,1,1,1,1,1,1,1,2,2,2,1,1};
        bestRules.add(bestRuleMoreMissingPortsweep);
        int[] bestRuleMissingBack = new int[]{37517,1,1,1,942,7598,0,1,1,53,57,73,52,85,0,20,99,100,1,2,2,1,1,1,1,1,1,1,2,2,1,1};
        bestRules.add(bestRuleMissingBack);
        int[] bestRuleMissingMoreNeptuneAndSatan = new int[]{54881,1,11,5,884,7806,0,3,0,0,31,1,8,100,71,100,100,72,1,1,1,1,2,2,1,2,2,1,1,1,1,1};
        bestRules.add(bestRuleMissingMoreNeptuneAndSatan);
        int[] bestRuleMissingWarezclient = new int[]{6055,1,14,1,246,8434,0,1,2,2,2,97,57,95,24,12,100,0,1,2,1,1,1,1,1,1,1,1,1,2,1,2};
        bestRules.add(bestRuleMissingWarezclient);
        int[] bestRuleMissingSatan = new int[]{6172,2,12,1,416,92,0,0,0,2,0,44,55,0,54,0,93,70,1,1,1,2,2,2,2,1,1,1,1,2,1,1}; //AGGIUNGE FALSI POSITIVI
        bestRules.add(bestRuleMissingSatan);
        int[] bestRuleMissingNmap = new int[]{43303,5808,0,0,0,920,24,6,0,17,43,2,11,1,1,1,1,2,1,1,1,2,1,1,2}; //Probe features
        bestRules.add(bestRuleMissingNmap);
        int[] bestRuleMoreMoreMissingPortsweep = new int[]{49018,24,0,0,1,232,12,1,81,93,63,73,8,1,1,2,2,1,1,1,1,1,1,2,2}; //Probe features
        bestRules.add(bestRuleMoreMoreMissingPortsweep);
        int[] bestRuleMoreProbe = new int[]{0,1303,1,2,0,840,14,5,2,0,26,23,3,1,1,1,1,1,1,1,1,1,2,2,2}; //Probe features
        bestRules.add(bestRuleMoreProbe);
        int[] bestRuleMoreMoreProbe = new int[]{13,125,1,0,0,0,0,0,0,0,98,255,1,1,1,1,2,1,1,1,1,1,2,1,1}; //Probe features
        bestRules.add(bestRuleMoreMoreProbe);
        int[] bestRuleMorePortsweep = new int[]{44943,247,0,0,0,58,22,7,42,98,1,48,9,1,1,1,1,1,1,1,1,1,1,2,2}; //Probe features
        bestRules.add(bestRuleMorePortsweep);
        int[] bestRuleMoreNeptune = new int[]{15464,1,6,5,457,9114,0,0,0,0,37,33,13,72,76,0,83,56,1,1,1,2,2,2,1,2,2,1,1,2,1,1}; //Probe features
        bestRules.add(bestRuleMoreNeptune);
        l=missingAttacksList(l, bestRules);
        System.out.println(l.size());
    run(l, 10000,1000);
    }
}
