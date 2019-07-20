import numpy as np
import sys 
#import re
import pandas as pd
import numpy as  np
#from sets import *
#rom multiprocessing import process
#from PIL.JpegImagePlugin import COM
import matplotlib.pyplot as plt
#from __builtin__ import True
#from docutils.nodes import header

#import seaborn as sns
Loc = "/home/tilak/ffmpeg_ads/ads_new_run/"


dataSnd=pd.read_csv(Loc+"sender_payload.csv", names=['Time', 'Seqnummer', 'Data', 'Fnumber' ])
dataSndRaw = dataSnd
dataSnd['Time']= dataSnd.Time.astype(float)*1000000
dataSnd['Time']= dataSnd.Time.astype(int)

dataSnd["DataConcat"]= dataSnd.Data+ ":"+ dataSnd.Data.shift(periods=-1,fill_value="").str.slice(stop=14)

dataSnd= dataSnd[dataSnd.DataConcat.str.contains("(?:01:6b:6f:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])+",regex=True )]
dataSnd["FramePTS"] = dataSnd.DataConcat.str.extract("(01:6b:6f:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])+" )
dataSnd["FramePTSInt"] = dataSnd.FramePTS.apply(lambda x: int(x.replace(":",""), 16))
dataSnd= dataSnd[dataSnd.FramePTSInt%10==0].drop_duplicates(subset='FramePTSInt')

headerSnd=["Time","FramePTSInt", "Fnumber"]
dataSnd.to_csv(Loc+"wireshark_server_PTS.log", sep =' ', index= False, header=False, columns=headerSnd)

dataframeNm=pd.read_csv(Loc+"sender_framenumber.csv", names=['Time', 'Seqnummer', 'Data', 'Fnumber'])
dataframeNm['Time'] = dataframeNm.Time.astype(float)*1000000
dataframeNm['Time'] = dataframeNm.Time.astype(int)


headerSeq_Send=["Time", "Fnumber",'Seqnummer']
dataframeNm.to_csv(Loc+"wireshark_server_seq_Fn.log", sep =' ', index= False, header=False, columns=headerSeq_Send)





dataRcv=pd.read_csv(Loc+"reciever.csv", names=['Time', 'Seqnummer', 'Data', 'Fnumber' ])
dataRcv['Time']=dataRcv.Time.astype(float)*1000000
dataRcv['Time']=dataRcv.Time.astype(int)
dataRcv["DataConcat"]= dataRcv.Data+ ":"+ dataRcv.Data.shift(periods=-1,fill_value="").str.slice(stop=14)
dataRcv= dataRcv[dataRcv.DataConcat.str.contains("(?:01:6b:6f:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])+",regex=True )]
dataRcv["FramePTS"] = dataRcv.DataConcat.str.extract("(01:6b:6f:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])+" )
dataRcv["FramePTSInt"] = dataRcv.FramePTS.apply(lambda x: int(x.replace(":",""), 16))
dataRcv= dataRcv[dataRcv.FramePTSInt%10==0].drop_duplicates(subset='FramePTSInt')
dataRcv['FramePTSInt']=dataRcv.FramePTSInt.astype(int)
dataRcv=dataRcv.sort_values('FramePTSInt')


headerRcv=["Time","FramePTSInt", "Fnumber"]
dataRcv.to_csv(Loc+"wireshark_reciever_PTS.log", sep =' ', index= False, header=False, columns=headerRcv)



dataRcvRaw= pd.read_csv(Loc+"reciever_raw.csv", names=['Time', 'Seqnummer', 'Data', 'Fnumber'])
dataRcvRaw['Time']=dataRcvRaw.Time.astype(float)*1000000
dataRcvRaw['Time']=dataRcvRaw.Time.astype(int)

headerRcvRaw = ["Time", "Fnumber",'Seqnummer']


dataRcvRaw.to_csv(Loc+"wireshark_reciever_seq_Fn.log", sep=' ', index=False, header=False, columns= headerRcvRaw)


dataRetransSnd = pd.read_csv(Loc+"sender_retransmissions.csv", names=['Time', 'Seqnummer', 'Data', 'Fnumber' ])

dataRetransSnd['Time'] = dataRetransSnd.Time.astype(float)*1000000
dataRetransSnd['Time'] = dataRetransSnd.Time.astype(int)

def frames_between_PTS(index):
    indexFPTS = dataSnd.index.astype(int)
    if(index =="start"):
            range_f= indexFPTS
            return dataSndRaw.loc[range_f[:-1]]
        
    elif(index=="end"):    
        range_l= indexFPTS -1
        return dataSndRaw.loc[range_l[1:]]


header_Snd = ["Time","FramePTSInt", "Fnumber"]
#dataSnd.to_csv(Loc+"python_generated_wireshark_server_test.log", sep=' ', index=False, header=False)
dataSnd.to_csv(Loc+"python_generated_wireshark_server_test.log", sep=' ', index=False, header=False, columns= header_Snd)



lowerIdEnd = frames_between_PTS("end")
lowerIdStart = frames_between_PTS("start")

lowerIdStart_head=lowerIdStart.head(len(lowerIdEnd))

dataFrameEnd = dataSndRaw.loc[(dataSnd.index.astype(int)-1)[1:]]
#print(dataSndRaw.loc[lowerIdStart:lowerIdEnd])
list_frame_start_end = list(zip(lowerIdStart.Fnumber,lowerIdEnd.Fnumber))
list_seq_start_end = list(zip(lowerIdStart.Seqnummer,lowerIdEnd.Seqnummer))


E_F_Delay= pd.DataFrame(columns=["FirstSegTime","LastSegTime"])
E_F_Delay['FirstSegTime'] = lowerIdStart.Time.tolist()
E_F_Delay['LastSegTime'] = lowerIdEnd.Time.tolist()
E_F_Delay['LastSeqNummer'] = lowerIdEnd.Seqnummer.tolist()
E_F_Delay['FirstSeqNummer'] = lowerIdStart.Seqnummer.tolist()#[:-1]



dataHiddenFrames=dataSndRaw.loc[[a for tpl in zip(lowerIdStart.index,lowerIdEnd.index) for a in range(tpl[0],tpl[1]+1)]]

dataHiddenFramesList= pd.DataFrame(list_frame_start_end, columns = ['FrameStart', 'FrameEnd'])

frameList={ 'Frange':[], 'Seqnummer':[]}

dataSndRaw.merge(dataRetransSnd,on="Seqnummer").Seqnummer#.drop_duplicates()


def extractHiddenFrames():
        for index, row in dataHiddenFramesList.iterrows():
            #frameList['sFrame'].append(dataHiddenFramesList.FrameStart)
            #print( row.FrameStart, row.FrameEnd)
             
            frameList['Frange'].append(dataSndRaw[(dataSndRaw.Fnumber>=row.FrameStart) & (dataSndRaw.Fnumber<=row.FrameEnd)].Fnumber.tolist())
            frameList['Seqnummer'].append(dataSndRaw[(dataSndRaw.Fnumber>=row.FrameStart) & (dataSndRaw.Fnumber<=row.FrameEnd)].Seqnummer.tolist())
            



extractHiddenFrames()            


print( frameList['Seqnummer'])
dataRetransSnd["RetxFlag"]= ""



for index,row in dataRetransSnd.iterrows():
    for item in frameList['Seqnummer']:
        #print(item)
        if row.Seqnummer in item:
            #print( str(item).strip('[]'))
            
            #dataRetransSnd['Seqnummer']=  pd.Series(item)
            dataRetransSnd['RetxFlag'].iloc[index]=str(item).strip('[]')
            break


E_F_Delay["Retxed"]= ""
prev_index1=-1;

for index, row in  dataRetransSnd.iterrows():
   for index1, row1 in E_F_Delay.iterrows():
       if int(row.RetxFlag.split()[0].strip(',')) == row1.FirstSeqNummer:
           print("row.time, index1  ", row.Time, index1)
           E_F_Delay['Retxed'].iloc[index1]= row.Time     

           if (index1 == prev_index1):
               
               print("INdex1 equal to last index", row.Seqnummer)
           elif (index1 != prev_index1):
               print("index1 != prev_index1",prev_index1 )
           prev_index1 = index1



       else:
            E_F_Delay['Retxed'].iloc[index1]= row1.LastSegTime
       
        

                 
            
            
            
            
            


            
           
      
           
       
        


#frameListDframe = pd.DataFrame.from_records(frameList['Seqnummer'], columns=['Seqnummer'])
#frameListWithRetr= pd.merge(dataRetransSnd,frameListDframe, left_index=True, right_index=True)






#
#[item for item in frameList['Seqnummer']] 
#
#dataRetransSnd = pd.read_csv(Loc+"sender_retransmissions.csv", names=['Time', 'Seqnummer', 'Data', 'Fnumber' ])
#
#retransmitted_Frames= {'FrameList':[]}

dup_Seq=dataSndRaw[dataSndRaw['Seqnummer'].duplicated()]#.Seqnummer#.tolist()
#dup_Seq_R=dataRetransSnd[dataRetransSnd['Seqnummer']]#.Seqnummer.tolist()


dup_Seq[~dup_Seq.Seqnummer.isin(dataRetransSnd.Seqnummer)]

dataRetransSnd[~dataRetransSnd.Seqnummer.isin(dup_Seq.Seqnummer)]

frawWithRetransm=[]


print("exited the extractHiddenFrames()")


    
    

#[item for item in dataRetransSnd['Seqnummer'].tolist() if item in frameList['Seqnummer']]



#n ={k: d[k] for k in frameList.keys() & dataRetransSnd['Seqnummer'].tolist()}


with open(Loc+"HiddenFrames.log", 'w') as f_out:
    for item in  frameList['Frange']:
        f_out.write("%s\t%i\n" % ("\t".join(map(str,item)), len(item)))



def extractDuplicateSeqNumberIndxnCountWithData(inFile, outFile1, outFile2, outFile3, outFile4, colNumWanttoRemDup):
    ## Reading Sequence number from the log file
    f = open(inFile,'r')
    out = f.readlines()
    f.close()
    #colNumWanttoRemDup = 2
    length = len(out)
    tempSeqN = []
    for i in range(0,length-1):
        temp1 = out[i].lstrip().split()
        #lengthDR = len(tempDR)
        tempSeqN.append(temp1[colNumWanttoRemDup])
    #print tempSeqN

    ##Extracting Unique SeqNumber
    tempUniqSeqN = []
    for i in tempSeqN:
        if i not in tempUniqSeqN:
            tempUniqSeqN.append(i)
    #print tempUniqSeqN

    # lenSeqN = len(tempSeqN)
    # lenUniqSeqN = len(tempUniqSeqN)
    # print "lenSeqN", lenSeqN , "lenUniqSeqN", lenUniqSeqN

    ##Finding duplicate index locations and counter
    seqListabtDup = []
    seqListabtDup_FN = []
    seqListabtDupsOnly = []
    dupSeqN_allFrames = []
    for k, item1 in enumerate(tempUniqSeqN):
        #print "k:", k, "tempUniqSeqN:", item1
        counter = 0
        seqListabtDup.append(item1 + "\t")
        seqListabtDup_FN.append(item1 + "\t")
        tdup = []
        tdup.append(item1+"\t")
        tdup2 = []
        for l, item2 in enumerate(tempSeqN):
            #print "l:", l, "tempSeqN:", item2
            if item1 == item2:
                temp2 = out[l].lstrip().split()
                seqListabtDup.append(str(l)+"\t")    #Adding duplicate index frame data
                seqListabtDup_FN.append(temp2[1]+"\t")    #Adding duplicate index locations
                tdup.append(temp2[1]+"\t")
                tdup2.append(temp2[1]+"\n")
                counter += 1
        if counter>1:
            seqListabtDupsOnly += tdup
            seqListabtDupsOnly.append(str(counter) + "\n")
            dupSeqN_allFrames += tdup2
            #dupSeqN_allFrames.append("\n")

        seqListabtDup.append(str(counter) + "\n")    #Number of duplicates of that instant
        seqListabtDup_FN.append(str(counter) + "\n")    #Number of duplicates of that instant

        #print "number of duplicates found for SeqN :", item1, "=is:", counter

    #writing the duplicates List
    f_out = open(outFile1,'w')
    f_out2 = open(outFile2,'w')
    for k, item in enumerate(seqListabtDup):
        #print seqListabtDup[k]
        f_out.write("%s" % seqListabtDup[k])
        f_out2.write("%s" % seqListabtDup_FN[k])
    f_out.close()
    f_out2.close()

    f_out3 = open(outFile3,'w')
    for item in seqListabtDupsOnly:
        f_out3.write("%s" % item)
    f_out3.close()

    f_out4 = open(outFile4,'w')
    for item in dupSeqN_allFrames:
        f_out4.write("%s" % item)
    f_out4.close()

E_G = {
        "Firstsegsender":[], 
        "Lastsegmentreceiver":[]
     }



#dup_Seq.symmetric_difference(dup_Seq_R, other='Seqnummer')
#print("retransimtted frames are", retransmitted_Frames)

#df = pd.concat([dup_Seq,dup_Seq_R], axis=1)




def computeDelaybnWiresharkSenderNRxer_Ext2(inFile1, inFile2, inFile3, inFile4, inFile5, outFile1):
    f_wsAF = open(inFile1,'r')
    ## Reading All frames  data in wireshark_server_TSnFNnSN
    #print("f_wsAF inFile1 ", inFile1)
    out_wsAF = f_wsAF.readlines()
    f_wsAF.close()
    length_wsAF = len(out_wsAF)

    f_wsHF = open(inFile2,'r')  ## Reading Hidden frames in pyGen_wireshark_server_HiddenFrames
    out_wsHF = f_wsHF.readlines()
    #print("out_wsHF inFile2 ", inFile2)

    f_wsHF.close()
    length_wsHF = len(out_wsHF)
    ##inFile3 contains the ethernet frame number of the receiver
    f_wAF = open(inFile3,'r') 
    #print("f_wAF inFile3 ", inFile3)
## Reading ALL frames data in pyGen_wireshark_TSnFNnSN
    out_wAF = f_wAF.readlines()
    f_wAF.close()
    length_wAF = len(out_wAF)

    f_wsDSeqN = open(inFile4,'r')  ## Reading Duplicate SeqNum data in pyGen_wireshark_server_seqDupListWithFNOnly.log
    out_wsDSeqN = f_wsDSeqN.readlines()
    #print("out_wsDSeqN inFile4 ", inFile4)

    f_wsDSeqN.close()
    length_wsDSeqN = len(out_wsDSeqN)

    f_wsDSFrN = open(inFile5,'r')  ## Reading Duplicate SeqNum Frame Numbers in pyGen_wireshark_server_seqDupListFN.log
    out_wsDSFrN = f_wsDSFrN.readlines()
    #print("out_wsDSFrN inFile5 ", inFile5)

    f_wsDSFrN.close()
    lengthws_DSFrN = len(out_wsDSFrN)

    ## Reading Duplicate SeqNum from pyGen_wireshark_server_seqDupList.log and creating a List
    tempws_DupSeqNL = []
    for k in range(0, length_wsDSeqN-1):
        temp1ws_SeqN = out_wsDSeqN[k].lstrip().split()
        tempws_DupSeqNL.append(temp1ws_SeqN[0])

    ## Reading Frame Numbers from pyGen_wireshark_server_TSnFNnSN and Creating a List
    tempws_FrN = []
    for k in range(0, length_wsAF-1):
        temp1ws_AF = out_wsAF[k].lstrip().split()
        tempws_FrN.append(temp1ws_AF[1])

    ## Reading Frame Numbers from pyGen_wireshark_TSnFNnSN and Creating a List
    tempw_SeqN = []
    for l in range(0, length_wAF-1):
        temp1w_AF = out_wAF[l].lstrip().split()
        tempw_SeqN.append(temp1w_AF[2])
        #print("tempw_SeqN before", tempw_SeqN)

    ## Reading Frame Numbers from pyGen_wireshark_server_seqDupListFN and Creating a List
    tempws_DupSeqFrN = []
    for m in range(0, lengthws_DSFrN-1):
        temp1ws_DSFrN = out_wsDSFrN[m].lstrip().split()
        tempws_DupSeqFrN.append(temp1ws_DSFrN[0])

    #print tempws_FrN
    #print tempw_SeqN
    #print tempws_DupSeqFrN
    #print tempws_DupSeqNL

    outBuf = []
    procd_rtxSeqN_FNList = []

    for j in range(0, length_wsHF-1):
        temp1ws_HF = out_wsHF[j].lstrip().split()
        len_HFline = len(temp1ws_HF)
        
        #print ("len_HFline",len_HFline)
        #if len_HFline <= 2:
            #print "len_HFline less than 2",len_HFline
        if len_HFline > 2:
            pts_wsHFcounter = int(temp1ws_HF[len_HFline-1])
            #print("pts_wsHFcounter", pts_wsHFcounter)
        else:
            #print("in the else case for the len_HFline < 2")
            pts_wsHFcounter = 0

        pts_wsFrN_FirstFr = temp1ws_HF[0]
        #print("pts_wsFrN_FirstFr",pts_wsFrN_FirstFr)
        pts_wsFrN_LastFr = temp1ws_HF[pts_wsHFcounter-1]
        #print (j, "FirstHframe:", pts_wsFrN_FirstFr, "LastHframe:", pts_wsFrN_LastFr)

        FlaggSF = False
        FlaggEF = False
        reTxmitFlagg = False

        if pts_wsHFcounter > 1:
            #print("tempws_FrN is", tempws_FrN)
            pts_wsFrN_FirstFr_Locin_ws_AF = tempws_FrN.index(pts_wsFrN_FirstFr)
            #print("pts_wsFrN_FirstFr_Locin_ws_AF", pts_wsFrN_FirstFr_Locin_ws_AF)
            pts_wsFrN_LastFr_Locin_ws_AF = tempws_FrN.index(pts_wsFrN_LastFr)
            #print("pts_wsFrN_LastFr_Locin_ws_AF", pts_wsFrN_FirstFr_Locin_ws_AF)


            if pts_wsFrN_FirstFr_Locin_ws_AF:    #Get the First Frame data
                temp1ws_AF = out_wsAF[pts_wsFrN_FirstFr_Locin_ws_AF].lstrip().split()
                tS_ws_SF = temp1ws_AF[0]
                fN_ws_SF = temp1ws_AF[1]
                seqN_ws_SF = temp1ws_AF[2]
                FlaggSF = True

            if pts_wsFrN_LastFr_Locin_ws_AF:   #Get the Last Frame data
                temp2ws_AF = out_wsAF[pts_wsFrN_LastFr_Locin_ws_AF].lstrip().split()
                #tS_ws_EF = temp2ws_AF[0]
                fN_ws_EF = temp2ws_AF[1]
                seqN_ws_EF = temp2ws_AF[2]
                #print "in get the last frame data:  seqN_ws_EF", seqN_ws_EF
                FlaggEF = True
            #print "pts_wsHFcounter", pts_wsHFcounter
            for n in range(0, pts_wsHFcounter+1): ##This part is to extract the retransmitted frame details
                Frame = temp1ws_HF[n]
                #print "Frame", Frame
                if Frame in tempws_DupSeqFrN:
                    if Frame not in procd_rtxSeqN_FNList:
                        pts_rtxF_Locin_ws_AF = tempws_FrN.index(Frame)
                        if pts_rtxF_Locin_ws_AF:
                            temp1ws_rtxF_line = out_wsAF[pts_rtxF_Locin_ws_AF].lstrip().split()
                            #tS_ws_rtxF = temp1ws_rtxF_line[0]
                            fN_ws_rtxF = temp1ws_rtxF_line[1]
                            seqN_ws_rtxF = temp1ws_rtxF_line[2]
                            reTxmitFlagg = True
                            #print "fN_ws_rtxF", fN_ws_rtxF
                            #print reTxmitFlagg
            if reTxmitFlagg:                     ##This part is to consider the last frame in the duplicates of sequence number in retransmitted frame
                if seqN_ws_rtxF in tempws_DupSeqNL:
                    seqN_ws_rtxF_Locin_tempws_DupSeqNL = tempws_DupSeqNL.index(seqN_ws_rtxF)
                    tempws_DupSeqNL_Line = out_wsDSeqN[seqN_ws_rtxF_Locin_tempws_DupSeqNL].lstrip().split()
                    len_tempws_DupSeqNL_Line = len(tempws_DupSeqNL_Line)
                    #print tempws_DupSeqNL_Line, len_tempws_DupSeqNL_Line
                    tempPrcFr = tempws_DupSeqNL_Line[1:len_tempws_DupSeqNL_Line-1] ##Check the line size limits  The follwoing 3 lines store the processed rtxFrames
                    #print "tempPrcFr",len_tempws_DupSeqNL_Line-2, tempPrcFr
                    for item1 in tempPrcFr:
                        procd_rtxSeqN_FNList.append(item1)
                    ##Look for the other sequence number, check if it is greater than the last frame in the hidden frame data 
                    other_temp1ws_rtxF = tempws_DupSeqNL_Line[len_tempws_DupSeqNL_Line-2]
                    #print "other_temp1ws_rtxF:", other_temp1ws_rtxF
                    if other_temp1ws_rtxF != fN_ws_rtxF:
                        pts_rtxF_Locin_ws_AF = tempws_FrN.index(other_temp1ws_rtxF)
                        if pts_rtxF_Locin_ws_AF:
                            temp1ws_rtxF_line = out_wsAF[pts_rtxF_Locin_ws_AF].lstrip().split()
                            #print temp1ws_rtxF_line
                            #tS_ws_rtxF = temp1ws_rtxF_line[0]
                            fN_ws_rtxF = temp1ws_rtxF_line[1]
                            seqN_ws_rtxF = temp1ws_rtxF_line[2]
                            #print "seqN_ws_rtxF", seqN_ws_rtxF
                            reTxmitFlagg = True
                            #print "other_temp1ws_rtxF", fN_ws_rtxF

            if FlaggSF&FlaggEF:
                if reTxmitFlagg:
                    if fN_ws_EF < pts_wsFrN_LastFr:
                        print("in reTxmit flag fN_ws_EF < pts_wsFrN_LastFr",fN_ws_EF, pts_wsFrN_LastFr) 
                        fN_ws_EF = pts_wsFrN_LastFr
                    seqN_ws_Locin_w_AF = tempw_SeqN.index(seqN_ws_rtxF)
                    #print seqN_ws_Locin_w_AF
                    fN_ws_EF = fN_ws_rtxF
                    #print "fN_ws_EF", fN_ws_EF
                    #if fN_ws_EF < pts_wsFrN_LastFr:
                        #fN_ws_EF = pts_wsFrN_LastFr
                    #print "fn_ws_EF,  pts_wsFrN_LastFr",fN_ws_EF,pts_wsFrN_LastFr
                    #print "seqN_ws_EF", seqN_ws_EF
                else:
                        seqN_ws_Locin_w_AF = tempw_SeqN.index(seqN_ws_EF)
                        print("in else from FlaggSF&FlaggEF & reTxmitFlagg", seqN_ws_Locin_w_AF )

                if seqN_ws_Locin_w_AF:
                        print("seqN_ws_Locin_w_AF", seqN_ws_Locin_w_AF);
                        if fN_ws_EF < pts_wsFrN_LastFr:
                            print("fN_ws_EF < pts_wsFrN_LastFr", fN_ws_EF, pts_wsFrN_LastFr)
                            fN_ws_EF = pts_wsFrN_LastFr
                            print("fN_ws_EF before last", fN_ws_EF)
                            seqN_ws_Locin_w_AF = tempw_SeqN.index(seqN_ws_EF)
                            #print "fN_ws_EF < pts_wsFrN_LastFr in else block"
                        #if  fN_ws_EF > pts_wsFrN_LastFr:   
                            #seqN_ws_Locin_w_AF = tempw_SeqN.index(seqN_ws_EF)
                            #print"seqN_ws_EF", seqN_ws_EF
                            #print "seqN_ws_Locin_w_AF", seqN_ws_Locin_w_AF
                            #print " if seqN_ws_Locin_w_AF: seqN_ws_Locin_w_AF", seqN_ws_Locin_w_AF
                        temp1w_AF = out_wAF[seqN_ws_Locin_w_AF].lstrip().split()
                        #print "temp1w_AF", temp1w_AF
                        tS_w_EF = temp1w_AF[0]
                        fN_w_EF = temp1w_AF[1]
                        print("fN_ws_EF_last", fN_ws_EF)
                        seqN_w_EF = temp1w_AF[2]
                        E_G['Firstsegsender'].append(tS_ws_SF)
                        E_G['Lastsegmentreceiver'].append(tS_w_EF)
                        diffSnRerTS = float(tS_w_EF) - float(tS_ws_SF)
                        diffSnRerTs_str = str(diffSnRerTS)
                        outBuf.append(fN_ws_SF + "\t" + fN_ws_EF + "\t" + seqN_ws_SF + "\t" + seqN_ws_EF + "\t" + seqN_w_EF + "\t" + fN_w_EF + "\t" + tS_ws_SF + "\t" + tS_w_EF + "\t" + diffSnRerTs_str + "\n")
                        
    f_outTSD = open(outFile1,'w')
    for item in outBuf:
        f_outTSD.write("%s" % item)
    f_outTSD.close()
 
    




f_s = open(Loc+"server_cut.log", 'r')
out= f_s.readlines()
B_sent = set();
Fdec = set();
k=0
snd = {
        "frameNum":[], 
        "sndTimestamp":[]
     }

rcvd={ 
      "frameNum":[], 
      "ffmdecTimestamp":[]
     }
bef_tcp_send={
     "frameNum":[], 
     "befSentTimestamp":[]
    }








temp_BySent=[]
temp_Tstamp= []
temp_FFMDEC2_Tstamp=[]
temp_FFMDEC2_Frame=[]

dup =set()
for i in range(0,len(out)-1):
    if "Bytes sent at time" in out[i]:
        temp_BySent = out[i].lstrip().split()
        #print temp_BySent[18]
        if temp_BySent[18] == "-1": continue
        snd["frameNum"].append(int(temp_BySent[18]))
        snd["sndTimestamp"].append(int(temp_BySent[11]))
        #if temp_BySent[18] not in B_sent:
            #B_sent.add(temp_BySent[18])   
            #print B_sent
        #B_sent.add(temp_BySent[18])
        #print "Bset is ", B_sent
    if "TEST FFMDEC2 ->" in out[i]:
        temp_FFMDec = out[i].lstrip().split();
        #print temp_FFMDec[8]
        rcvd["frameNum"].append(int(temp_FFMDec[8]))
        rcvd["ffmdecTimestamp"].append(int(temp_FFMDec[11]))
    
    if "The len sent before" in out[i]:
        temp_bef_TcpSend = out[i].lstrip().split();
        if temp_bef_TcpSend[17]=="-1": 
            #print "continuing"
            continue
        if int(temp_bef_TcpSend[17]) not in dup:
            dup.add(int(temp_bef_TcpSend[17]))
            #print temp_bef_TcpSend[17], temp_bef_TcpSend[20]
        #print temp_bef_TcpSend[17], temp_bef_TcpSend[20]
            bef_tcp_send["frameNum"].append(int(temp_bef_TcpSend[17]))
            bef_tcp_send["befSentTimestamp"].append(int(temp_bef_TcpSend[20]))

        #temp5 = out[i+1].lstrip().split();
        
        #if temp_BySent[18] not in Fdec:
            #Fdec.add(temp_FFMDec[8]) 
data= pd.DataFrame(snd)

#print len(data)
data1= pd.DataFrame(rcvd)
data2= pd.DataFrame(bef_tcp_send)
#print len(data2)
datajoint = data.merge(data1, on="frameNum" ).merge(data2,on="frameNum")
#datajoint['Framenumber', 'BytesSent','FFMDec', 'Bef_TCPSnd()']=datajoint
#print(datajoint)  
  
inFile1 = Loc+"wireshark_server_seq_Fn.log"
inFile2 = Loc+"HiddenFrames.log"
inFile3 = Loc+"wireshark_reciever_seq_Fn.log"

###May 25 #updated on May29
outFile1 = Loc+"pyGen_wireshark_server_seqDupListIndex.log"
outFile2 = Loc+"pyGen_wireshark_server_seqDupListSNFNAll.log"
outFile3 = Loc+"pyGen_wireshark_server_seqDupListSNFNOnly.log"
outFile4 = Loc+"pyGen_wireshark_server_seqDupListFN.log"
colNumWanttoRemDup = 2
extractDuplicateSeqNumberIndxnCountWithData(inFile1, outFile1, outFile2, outFile3, outFile4, colNumWanttoRemDup)

#print("Exited the DuplicateseqNr")

inFile4 = Loc+"pyGen_wireshark_server_seqDupListSNFNOnly.log"
inFile5 = Loc+"pyGen_wireshark_server_seqDupListFN.log"
outFile1 = Loc+"py_Gen_WiresharkRecieverNSender_TSD.log"


#computeDelaybnWiresharkSenderNRxer_Ext2(inFile1, inFile2, inFile3, inFile4, inFile5, outFile1)
#print("Exited the Delaycalculation")
   
finalDelayEst= pd.DataFrame(E_G, columns = ['Firstsegsender', 'Lastsegmentreceiver'])

D_F= pd.merge(datajoint,finalDelayEst, left_index=True, right_index=True)
#print(D_F)

#D_F['E_G']= (D_F.Lastsegmentreceiver.astype(float)-D_F.Firstsegsender.astype(float))/1000
#D_F['E_F']= (D_F.Firstsegsender.astype(float)-D_F.befSentTimestamp.astype(float))/1000

#sns.lmplot("Framenumber", "Delay ", data=finalDelayEst, col='E_F')
#print(D_F)

#D_F.to_csv(Loc+"Measurementpoints_D_H.log", sep=' ', index=False, header=True)

#fig = plt.figure(1)
#plt.figure(1)
#plt.xlabel('frame number')
#plt.ylabel('latency in msec')
#plt.ylim((0:))
#plt.xlim((0,2000))

#plt.legend( loc='upper left', numpoints = 1,prop={'size':6.5} )
#fig.savefig('delay_E_F.png')
#x=D_F.index
#y=D_F.E_G
#plt.plot(D_F.index,D_F.E_G, label="E-->G")


#plt.plot(D_F.index,D_F.E_F, label="E-->F")


#plt.show()



sys.exit()
