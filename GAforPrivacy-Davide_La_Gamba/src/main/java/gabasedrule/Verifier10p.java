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

import static gabasedrule.Verifier.*;
import static io.jenetics.engine.EvolutionResult.toBestPhenotype;

public class Verifier10p {

    public static final Integer EQUALS=3;
    public static Double A;
    public static Double B;
    private static HashMap<String, Integer> mapAttacks = new HashMap<>();
    private static HashMap<String, Integer> mapFound = new HashMap<>();
    private static List<Connection> l;

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

    public static void main(String[] args) throws IOException {
        l=DatasetLoader.parse(new File("src/main/resources/kddcup99_csv.csv"));
//        l=DatasetLoader.parse(new File("src/main/resources/kddcup.data.corrected.csv"));
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
        int[] bestRuleDos1= new int[]{34381, 1, 12, 5, 984, 3538, 0, 1, 1, 0, 40, 0, 15, 100, 89, 100, 100, 87, 1, 1, 1, 1, 1, 2, 1, 2, 2, 1, 1, 1, 1, 1};
        int[] bestRuleDos2= new int[]{5855, 3, 10, 1, 462, 8249, 0, 2, 0, 1, 1, 81, 27, 88, 31, 100, 90, 100, 1, 2, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1};
        int[] bestRuleDos3= new int[]{33825, 1, 12, 3, 103, 3745, 0, 1, 2, 1, 1, 67, 68, 18, 60, 0, 100, 0, 1, 1, 1, 1, 1, 2, 2, 1, 1, 2, 2, 2, 1, 1};
        int[] bestRuleDos4= new int[]{56792, 1, 1, 5, 135, 6403, 0, 1, 0, 10, 98, 97, 18, 39, 86, 100, 31, 66, 1, 1, 1, 1, 1, 2, 1, 2, 2, 1, 1, 1, 1, 1};
        int[] bestRuleDos5= new int[]{7989, 2, 12, 1, 101, 1594, 0, 3, 2, 1, 0, 99, 70, 0, 8, 3, 95, 39, 1, 1, 1, 1, 1, 2, 2, 1, 1, 2, 1, 2, 1, 1};
        int[] bestRuleDos6= new int[]{41314, 1, 11, 3, 328, 4527, 0, 0, 3, 76, 41, 0, 95, 100, 29, 3, 40, 58, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 2, 1, 2, 1};
        int[] bestRuleDos7= new int[]{52628, 1, 12, 8, 341, 8236, 0, 0, 1, 0, 35, 1, 20, 100, 0, 0, 100, 25, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 2, 2, 1, 1};
        int[] bestRuleDos8= new int[]{33571, 1, 12, 7, 294, 353, 0, 1, 3, 1, 36, 50, 18, 55, 13, 38, 23, 14, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 2, 1, 1, 1};
        int[] bestRuleDos9= new int[]{40960, 1, 11, 5, 842, 7092, 0, 2, 1, 1, 61, 1, 54, 99, 77, 80, 100, 37, 1, 1, 1, 1, 1, 2, 1, 2, 2, 1, 1, 1, 1, 1};
        int[] bestRuleDos10= new int[]{55183, 1, 1, 1, 807, 1373, 0, 3, 1, 99, 97, 5, 67, 40, 90, 16, 42, 100, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1};
        int[] bestRuleDos11= new int[]{34177, 3, 8, 1, 26, 2571, 0, 1, 2, 99, 97, 35, 0, 88, 1, 2, 69, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 2, 1, 2};
        int[] bestRuleProbe1= new int[]{3290, 5389, 0, 2, 0, 184, 2, 6, 100, 53, 100, 13, 5, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2};
        int[] bestRuleProbe2= new int[]{226, 5306, 0, 0, 2, 938, 17, 7, 54, 30, 57, 236, 3, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 2, 2};
        int[] bestRuleProbe3= new int[]{56855, 16, 1, 0, 2, 0, 1, 3, 100, 74, 94, 14, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        int[] bestRuleProbe4= new int[]{42895, 9875, 0, 1, 0, 146, 15, 0, 74, 100, 96, 2, 7, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2};
        int[] bestRuleU2r1= new int[]{26427, 6, 2731, 1, 0, 1, 648, 4, 2, 57, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        int[] bestRuleU2r2= new int[]{17906, 350, 1185, 1, 0, 2, 170, 0, 0, 100, 200, 1, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1};
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
    }
}
