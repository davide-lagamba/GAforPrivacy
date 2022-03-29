package gabasedrule;

import gabasedrule.utils.Connection;
import gabasedrule.utils.DatasetLoader;
import io.jenetics.*;
import io.jenetics.engine.Engine;
import io.jenetics.engine.EvolutionStatistics;
import io.jenetics.util.Factory;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static io.jenetics.engine.EvolutionResult.toBestPhenotype;
import static io.jenetics.engine.Limits.byExecutionTime;

public class RunnerConfig4 {

    public static final Integer EQUALS=3;
    public static final Integer LESSER=1;
    public static final Integer GREATER=2;
    public static Double A;
    public static Double B;
    private static HashMap<String, Integer> mapAttacks = new HashMap<>();
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

    private static List<Connection> l;
    static ArrayList<Double> performace(final Genotype<IntegerGene> gt){
        Double TP=0.0, TN=0.0, FP=0.0, FN=0.0;
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
                    TP++;
                }else{
                    FP++;}
            }else{
                if(!(c.getLabel().equalsIgnoreCase("normal"))){
                    FN++;
                }else{
                    TN++;
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
                    if(mapFoundTmp.containsKey(c.getLabel())){
                        if(mapFoundTmp.get(c.getLabel())!=null) {
                            Object o =mapFoundTmp.get(c.getLabel());
                            if(o!=null){
                                n= (Integer) o;
                            }
                        }
                    }
                    mapFoundTmp.put(c.getLabel(), n+1);
                }else{
                    a = a + 1;}
            }
        }
        Double value =  (ab/A)-(a/B);
        if(value.isNaN())
            return 0.0;
        if(value>bestFitness){
            bestFitness=value;
            mapFound=(HashMap<String, Integer>) mapFoundTmp.clone();
        }
        return value;
    }
    public static void main(String[] args) throws IOException {
        l=DatasetLoader.parse(new File("src/main/resources/kddcup99_csv.csv"));
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
        System.out.println("Number of attacks: "+A+"\nNumber of normal connections: "+B);
        System.out.println("Attacks: "+mapAttacks.toString());
        final Factory<Genotype<IntegerGene>> GTF = Genotype.of(
                IntegerChromosome.of(0, 58330),
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
                RunnerConfig4::fitness,
                GTF).populationSize(1000)
                .selector(new EliteSelector<>())
                .optimize(Optimize.MAXIMUM)
                .alterers(
                        new Mutator<>(0.4),
                        new MultiPointCrossover<>(0.8, 5)
                ).build();

        final EvolutionStatistics<Double, ?>
                statistics= EvolutionStatistics.ofNumber();

        final Phenotype<IntegerGene, Double> best= engine.stream()
                 .limit(byExecutionTime(Duration.ofMinutes(120)))
                .peek(statistics)
                .collect(toBestPhenotype());

        System.out.println(statistics);
        System.out.println(best);
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
}
