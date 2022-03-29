package gabasedrule;

import gabasedrule.utils.Connection;
import gabasedrule.utils.DatasetLoader;
import io.jenetics.*;
import io.jenetics.engine.Engine;
import io.jenetics.engine.EvolutionStatistics;
import io.jenetics.util.Factory;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static io.jenetics.engine.EvolutionResult.toBestPhenotype;

public class RunnerConfig2 {

    public static final Integer EQUALS=3;
    public static final Integer LESSER=1;
    public static final Integer GREATER=2;
    public static Double A;
    public static Double B;

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
    static Double fitness(final Genotype<IntegerGene> gt){
        Double a=0.0, ab=0.0;
        for(Connection c: l){
            if((compare(c.getDuration(),gt.get(0).get(0).allele(), LESSER)) &&
                    (compare(c.getProtocolType(),gt.get(1).get(0).allele(), EQUALS)) &&
                    (compare(c.getService(),gt.get(2).get(0).allele(), EQUALS)) &&
                    (compare(c.getFlag(), gt.get(3).get(0).allele(), EQUALS)) &&
                    (compare(c.getSrcBytes(), gt.get(4).get(0).allele(), LESSER)) &&
                    (compare(c.getDstBytes(),gt.get(5).get(0).allele(), LESSER)) &&
                    (compare(c.getLand(), gt.get(6).get(0).allele(), EQUALS)) &&
                    (compare(c.getWrongFragment(),gt.get(7).get(0).allele(), LESSER)) &&
                    (compare(c.getUrgent(),gt.get(7).get(1).allele(), LESSER)) &&
                    (compare(c.getCount(),gt.get(8).get(0).allele(), GREATER)) &&
                    (compare(c.getSrvCount(),gt.get(8).get(1).allele(), LESSER)) &&
                    (compare(c.getSerrorRate(),gt.get(9).get(0).allele(), gt.get(10).get(7).allele())) &&
                    (compare(c.getSrvSerrorRate(),gt.get(9).get(1).allele(), gt.get(10).get(8).allele())) &&
                    (compare(c.getRerrorRate(),gt.get(9).get(2).allele(), gt.get(10).get(9).allele())) &&
                    (compare(c.getSrvRerrorRate(),gt.get(9).get(3).allele(), gt.get(10).get(10).allele())) &&
                    (compare(c.getSameSrvRate(),gt.get(9).get(4).allele(), LESSER)) &&
                    (compare(c.getDiffSrvRate(),gt.get(9).get(5).allele(), LESSER)) &&
                    (compare(c.getSrvDiffHostRate(),gt.get(9).get(6).allele(), LESSER))) {

                if (!(c.getLabel().equalsIgnoreCase("normal"))) {
                    ab = ab + 1;
                }else{
                    a = a + 1;}
            }
        }
        Double value =  (ab/A)-(a/B);
        if(value.isNaN())
            return 0.0;
        return value;
    }
    public static void main(String[] args) throws IOException {
        l=DatasetLoader.parse(new File("src/main/resources/kddcup99_csv.csv"));
        A=B=0.0;
        for(Connection c: l){
            if(c.getLabel().equalsIgnoreCase("normal"))
                B++;
            else {A++;}
        }
        System.out.println("Number of attacks: "+A+"\nNumber of normal connections: "+B);
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
                RunnerConfig2::fitness,
                GTF).populationSize(1000)
                .selector(new EliteSelector<>())
                .optimize(Optimize.MAXIMUM)
                .alterers(
                        new Mutator<>(0.4),
                        new MultiPointCrossover<>(0.8,4)
                ).build();

        final EvolutionStatistics<Double, ?>
                statistics= EvolutionStatistics.ofNumber();

        final Phenotype<IntegerGene, Double> best= engine.stream()
                .limit(1000)
                .peek(statistics)
                .collect(toBestPhenotype());

        System.out.println(statistics);
        System.out.println(best);
    }
}
