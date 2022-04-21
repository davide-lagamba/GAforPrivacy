package gabasedrule;

import gabasedrule.utils.Connection;
import gabasedrule.utils.DatasetLoader;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;

public class RandomClassifier {

    static ArrayList<Connection> l;
    static ArrayList<Double> randomClassifySpecificAttacks(ArrayList<Connection> l) {
        Double TP = 0.0, TN = 0.0, FP = 0.0, FN = 0.0;
        int random;
        for (Connection c : l) {
            random = ((int) (Math.random() * 1000)) % 5;
            if (random == 0) {
                if (c.getLabel().equalsIgnoreCase("normal"))
                    TN++;
                else FN++;
            } else {
                if (random == 1) {
                    if ((c.getLabel().equalsIgnoreCase("ipsweep")) || (c.getLabel().equalsIgnoreCase("nmap")) ||
                            (c.getLabel().equalsIgnoreCase("portsweep")) || (c.getLabel().equalsIgnoreCase("satan")))
                        TP++;
                    else
                        FP++;
                }
                if (random == 2) {
                    if((c.getLabel().equalsIgnoreCase("back")) || (c.getLabel().equalsIgnoreCase("land")) || (c.getLabel().equalsIgnoreCase("neptune")) ||
                            (c.getLabel().equalsIgnoreCase("pod")) || (c.getLabel().equalsIgnoreCase("smurf")) || (c.getLabel().equalsIgnoreCase("teardrop")))
                        TP++;
                    else
                        FP++;
                }
                if (random == 3) {
                    if((c.getLabel().equalsIgnoreCase("buffer_overflow")) || (c.getLabel().equalsIgnoreCase("loadmodule")) || (c.getLabel().equalsIgnoreCase("perl")) ||
                            (c.getLabel().equalsIgnoreCase("rootkit")))
                        TP++;
                    else
                        FP++;
                }
                if (random == 4) {
                    if((c.getLabel().equalsIgnoreCase("ftp_write")) || (c.getLabel().equalsIgnoreCase("guess_passwd")) || (c.getLabel().equalsIgnoreCase("imap")) ||
                            (c.getLabel().equalsIgnoreCase("multihop")) || (c.getLabel().equalsIgnoreCase("phf")) || (c.getLabel().equalsIgnoreCase("spy")) ||
                            (c.getLabel().equalsIgnoreCase("warezclient")) || (c.getLabel().equalsIgnoreCase("warezmaster")))
                        TP++;
                    else
                        FP++;
                }

            }

        }

        ArrayList<Double> results= new ArrayList<>();
        results.add(TP);
        results.add(TN);
        results.add(FP);
        results.add(FN);
        return results;
    }

    static ArrayList<Double> randomClassifySpecificWeightedAttacks(ArrayList<Connection> l, ArrayList<Double> percentages) {
        Double TP = 0.0, TN = 0.0, FP = 0.0, FN = 0.0;
        Double random;
        for (Connection c : l) {
            random = Math.random();
            if (random<=percentages.get(0)) {
                if (c.getLabel().equalsIgnoreCase("normal"))
                    TN++;
                else FN++;
            } else {
                if (random> percentages.get(0) && random<= percentages.get(0)+percentages.get(1)) {
                    if ((c.getLabel().equalsIgnoreCase("ipsweep")) || (c.getLabel().equalsIgnoreCase("nmap")) ||
                            (c.getLabel().equalsIgnoreCase("portsweep")) || (c.getLabel().equalsIgnoreCase("satan")))
                        TP++;
                    else
                        FP++;
                }
                if (random> percentages.get(0)+percentages.get(1) && random<= percentages.get(0)+percentages.get(1)+percentages.get(2)) {
                    if((c.getLabel().equalsIgnoreCase("back")) || (c.getLabel().equalsIgnoreCase("land")) || (c.getLabel().equalsIgnoreCase("neptune")) ||
                            (c.getLabel().equalsIgnoreCase("pod")) || (c.getLabel().equalsIgnoreCase("smurf")) || (c.getLabel().equalsIgnoreCase("teardrop")))
                        TP++;
                    else
                        FP++;
                }
                if (random> percentages.get(0)+percentages.get(1)+percentages.get(2) && random<= percentages.get(0)+percentages.get(1)+percentages.get(2)+percentages.get(3)) {
                    if((c.getLabel().equalsIgnoreCase("buffer_overflow")) || (c.getLabel().equalsIgnoreCase("loadmodule")) || (c.getLabel().equalsIgnoreCase("perl")) ||
                            (c.getLabel().equalsIgnoreCase("rootkit")))
                        TP++;
                    else
                        FP++;
                }
                if (random> percentages.get(0)+percentages.get(1)+percentages.get(2)+percentages.get(3) && random<= percentages.get(0)+percentages.get(1)+percentages.get(2)+percentages.get(3)+percentages.get(4)) {
                    if((c.getLabel().equalsIgnoreCase("ftp_write")) || (c.getLabel().equalsIgnoreCase("guess_passwd")) || (c.getLabel().equalsIgnoreCase("imap")) ||
                            (c.getLabel().equalsIgnoreCase("multihop")) || (c.getLabel().equalsIgnoreCase("phf")) || (c.getLabel().equalsIgnoreCase("spy")) ||
                            (c.getLabel().equalsIgnoreCase("warezclient")) || (c.getLabel().equalsIgnoreCase("warezmaster")))
                        TP++;
                    else
                        FP++;
                }

            }

        }

        ArrayList<Double> results= new ArrayList<>();
        results.add(TP);
        results.add(TN);
        results.add(FP);
        results.add(FN);
        return results;
    }

    static ArrayList<Double> randomClassifyGenericsWeightedAttacks(ArrayList<Connection> l, ArrayList<Double> percentages) {
        Double TP = 0.0, TN = 0.0, FP = 0.0, FN = 0.0;
        Double random;
        for (Connection c : l) {
            random = Math.random();
            if (random<=percentages.get(0)) {
                if (c.getLabel().equalsIgnoreCase("normal"))
                    TN++;
                else FN++;
            } else {
                if(!(c.getLabel().equalsIgnoreCase("normal"))){
                    TP++;
                }else{
                    FP++;
                }

            }


        }

        ArrayList<Double> results= new ArrayList<>();
        results.add(TP);
        results.add(TN);
        results.add(FP);
        results.add(FN);
        return results;
    }


    static ArrayList<Double> findPercentages(ArrayList<Connection> l) {
        Double dos = 0.0, probe = 0.0, u2r = 0.0, r2l = 0.0, normal=0.0;
        for (Connection c : l) {
                if (c.getLabel().equalsIgnoreCase("normal"))
                   normal++;

                    if ((c.getLabel().equalsIgnoreCase("ipsweep")) || (c.getLabel().equalsIgnoreCase("nmap")) ||
                            (c.getLabel().equalsIgnoreCase("portsweep")) || (c.getLabel().equalsIgnoreCase("satan")))
                       probe++;


                    if((c.getLabel().equalsIgnoreCase("back")) || (c.getLabel().equalsIgnoreCase("land")) || (c.getLabel().equalsIgnoreCase("neptune")) ||
                            (c.getLabel().equalsIgnoreCase("pod")) || (c.getLabel().equalsIgnoreCase("smurf")) || (c.getLabel().equalsIgnoreCase("teardrop")))
                        dos++;


                    if((c.getLabel().equalsIgnoreCase("buffer_overflow")) || (c.getLabel().equalsIgnoreCase("loadmodule")) || (c.getLabel().equalsIgnoreCase("perl")) ||
                            (c.getLabel().equalsIgnoreCase("rootkit")))
                        u2r++;

                    if((c.getLabel().equalsIgnoreCase("ftp_write")) || (c.getLabel().equalsIgnoreCase("guess_passwd")) || (c.getLabel().equalsIgnoreCase("imap")) ||
                            (c.getLabel().equalsIgnoreCase("multihop")) || (c.getLabel().equalsIgnoreCase("phf")) || (c.getLabel().equalsIgnoreCase("spy")) ||
                            (c.getLabel().equalsIgnoreCase("warezclient")) || (c.getLabel().equalsIgnoreCase("warezmaster")))
                        r2l++;
                }
        Double total= dos+probe+u2r+r2l+normal;

        ArrayList<Double> results= new ArrayList<>();
        results.add(normal/total);
        results.add(probe/total);
        results.add(dos/total);
        results.add(u2r/total);
        results.add(r2l/total);
        return results;
    }

    static ArrayList<Double> randomClassifyGenericsAttacks(ArrayList<Connection> l) {
        Double TP = 0.0, TN = 0.0, FP = 0.0, FN = 0.0;
        int random;
        for (Connection c : l) {
            random = ((int) (Math.random() * 1000)) % 5;
            if (random == 0) {
                if (c.getLabel().equalsIgnoreCase("normal"))
                    TN++;
                else FN++;
            } else {
                if(!(c.getLabel().equalsIgnoreCase("normal"))){
                    TP++;
                }else{
                    FP++;
                }

            }

        }

        ArrayList<Double> results= new ArrayList<>();
        results.add(TP);
        results.add(TN);
        results.add(FP);
        results.add(FN);
        return results;
    }

    public static void main(String[] args) throws IOException {
        int rep=100;
        ArrayList<Double> results;
        l = (ArrayList<Connection>) DatasetLoader.parse(new File("src/main/resources/kddcup99_csv.csv"));
        Double accuracy=0.0;
        Double detectionRate=0.0;
        Double falseAlarms=0.0;
        Double precision=0.0;
        Double specificity=0.0;
        Double MCC=0.0;
        Double tmpaccuracy=0.0;
        Double tmpdetectionRate=0.0;
        Double tmpfalseAlarms=0.0;
        Double tmpprecision=0.0;
        Double tmpspecificity=0.0;
        Double tmpMCC=0.0;
        Double TP=0.0;
        Double TN=0.0;
        Double FP=0.0;
        Double FN=0.0;
       for(int i=0; i<rep; i++){
        results= randomClassifySpecificAttacks(l);
         TP= results.get(0);
         TN= results.get(1);
         FP= results.get(2);
         FN= results.get(3);
           tmpaccuracy += ((TP+TN)/(TP+TN+FP+FN));
           tmpdetectionRate += (TP)/(FN+TP);
           tmpfalseAlarms+= (FP)/(TN+FP);
           tmpprecision += (TP)/(TP+FP);
           tmpspecificity+=TN/(TN+FP);
           tmpMCC+= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));}

        accuracy=tmpaccuracy/rep;
        detectionRate=tmpdetectionRate/rep;
        falseAlarms=tmpfalseAlarms/rep;
        precision=tmpprecision/rep;
        specificity=tmpspecificity/rep;
        MCC=tmpMCC/rep;
        System.out.println("Risultati relativi ad attacchi specifici classificati casualmente:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);


        tmpaccuracy=0.0;
        tmpdetectionRate=0.0;
        tmpfalseAlarms=0.0;
        tmpprecision=0.0;
        tmpspecificity=0.0;
        tmpMCC=0.0;
        for(int i=0; i<rep; i++){
            results= randomClassifyGenericsAttacks(l);
            TP= results.get(0);
            TN= results.get(1);
            FP= results.get(2);
            FN= results.get(3);
            tmpaccuracy += ((TP+TN)/(TP+TN+FP+FN));
            tmpdetectionRate += (TP)/(FN+TP);
            tmpfalseAlarms+= (FP)/(TN+FP);
            tmpprecision += (TP)/(TP+FP);
            tmpspecificity+=TN/(TN+FP);
            tmpMCC+= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));}

        accuracy=tmpaccuracy/rep;
        detectionRate=tmpdetectionRate/rep;
        falseAlarms=tmpfalseAlarms/rep;
        precision=tmpprecision/rep;
        specificity=tmpspecificity/rep;
        MCC=tmpMCC/rep;
        System.out.println("///////////");
        System.out.println("Risultati relativi ad attacchi generici classificati casualmente:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);

        tmpaccuracy=0.0;
        tmpdetectionRate=0.0;
        tmpfalseAlarms=0.0;
        tmpprecision=0.0;
        tmpspecificity=0.0;
        tmpMCC=0.0;
        ArrayList<Double> percentages = findPercentages(l);
        System.out.println("Percentuali\nnormal: "+percentages.get(0)+"\nprobe: "+percentages.get(1)+"\ndos: "+percentages.get(2)+"\nu2r: "+percentages.get(3)+"\nr2l: "+percentages.get(4));
        for(int i=0; i<rep; i++){
            results= randomClassifySpecificWeightedAttacks(l, percentages);
            TP= results.get(0);
            TN= results.get(1);
            FP= results.get(2);
            FN= results.get(3);
            tmpaccuracy += ((TP+TN)/(TP+TN+FP+FN));
            tmpdetectionRate += (TP)/(FN+TP);
            tmpfalseAlarms+= (FP)/(TN+FP);
            tmpprecision += (TP)/(TP+FP);
            tmpspecificity+=TN/(TN+FP);
            tmpMCC+= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));}

        accuracy=tmpaccuracy/rep;
        detectionRate=tmpdetectionRate/rep;
        falseAlarms=tmpfalseAlarms/rep;
        precision=tmpprecision/rep;
        specificity=tmpspecificity/rep;
        MCC=tmpMCC/rep;
        System.out.println("///////////");
        System.out.println("Risultati relativi ad attacchi specifici pesati classificati casualmente:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);

        tmpaccuracy=0.0;
        tmpdetectionRate=0.0;
        tmpfalseAlarms=0.0;
        tmpprecision=0.0;
        tmpspecificity=0.0;
        tmpMCC=0.0;
        for(int i=0; i<rep; i++){
            results= randomClassifyGenericsWeightedAttacks(l, percentages);
            TP= results.get(0);
            TN= results.get(1);
            FP= results.get(2);
            FN= results.get(3);
            tmpaccuracy += ((TP+TN)/(TP+TN+FP+FN));
            tmpdetectionRate += (TP)/(FN+TP);
            tmpfalseAlarms+= (FP)/(TN+FP);
            tmpprecision += (TP)/(TP+FP);
            tmpspecificity+=TN/(TN+FP);
            tmpMCC+= ((TP*TN)-(FP*FN))/Math.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN));}

        accuracy=tmpaccuracy/rep;
        detectionRate=tmpdetectionRate/rep;
        falseAlarms=tmpfalseAlarms/rep;
        precision=tmpprecision/rep;
        specificity=tmpspecificity/rep;
        MCC=tmpMCC/rep;
        System.out.println("///////////");
        System.out.println("Risultati relativi ad attacchi generici pesati classificati casualmente:");
        System.out.println("TP: "+TP+", TN: "+TN+", FP: "+FP+", FN: "+FN);
        System.out.println("Accuracy: "+accuracy);
        System.out.println("Detection Rate/Recall: "+detectionRate);
        System.out.println("False Alarms: "+falseAlarms);
        System.out.println("Precision: "+precision);
        System.out.println("Specificity: "+specificity);
        System.out.println("MCC: "+MCC);
    }
}
