#!/usr/bin/env python
# a bar plot with errorbars
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt

mpl.rcParams['pdf.fonttype'] = 42
N = 7

pkt_size     = np.array ([64,  128, 256, 512, 1024, 1456,  64.*7/12 + 594.*4/12 + 1456.*1/12])
out_pkt_size = np.array ([114, 178, 306, 562, 1074, 1506, 114.*7/12 + 658.*4/12 + 1506.*1/12])

# 64, 128, 256, iMix
fps = np.array ([8.84, 5.71, 3.06, 1.59, 0.81, 0.571, 2.18])
bps = np.array ([9.76, 9.22, 8.08, 7.44, 7.10, 7.00,  7.58])

tx_fps = np.array ([13.1, 8.45, 4.53, 2.35, 1.20, 0.85, 3.22])
tx_bps = np.array ([8.8, 10, 10, 10, 10, 10, 10, 10])

baseline_fps = tx_fps
baseline_bps = np.multiply ((out_pkt_size + 20) * 8. /1000, baseline_fps)

#ind = [0, 1, -2, -1]
ind = [0, 1, 2,3,4,5,6]
fps = fps[ind]
bps = bps[ind]
baseline_fps = baseline_fps[ind]
baseline_bps = baseline_bps[ind]

ind = np.arange(0, N)  # the x locations for the groups
width = 0.85       # the width of the bars
margin = 0.1

#colors = ['#edf7f6', '#acd9bb', '#d9bfdb']
colors = ['#c2a5cf',
'#f7f7f7',
'#a6dba0',
'#008837']

fig, ax = plt.subplots()
#rects1 = ax.bar(ind - width, baseline_fps, width, color='#edf7f6', zorder=3)
rects1 = ax.bar(ind - width*0.5 - margin*0.4, baseline_fps, width+margin*0.8, color=colors[0], zorder=3, edgecolor=colors[0])
rects2 = ax.bar(ind -width*0.5, fps, width, color=colors[2], zorder=3)

#rects3 = ax.bar(ind + width*2+0.06, chacha_fps, width, color='#d9bfdb', zorder=3)

# add some text for labels, title and axes ticks
ax.set_ylabel('Throughput (Mpps)', fontsize=24)
#ax.set_title('Scores by group and gender')
ax.set_xticks(ind)
ax.set_xticklabels(('64 B', '128 B', '256 B', '512 B', '1024 B', '1456 B', 'iMIX'), fontsize=20)
#ax.set_xticklabels(('70 B', '128 B', '256 B', '512 B', 'iMix'), fontsize=28)
ax.margins(0.08, 0)
ax.yaxis.grid(True,zorder=0, color='#dedede', linestyle='-')

ax.legend((rects1[0], rects2[0]), ('Baseline', 'IPsec Outbound Traffic'), fontsize=22)
plt.yticks(np.arange(0, 16, 2))
plt.tick_params(axis='y', which='major', labelsize=20)

ax.set_xlim([-width*0.5 - margin, ind[-1]+width*0.5+margin])
ax.set_ylim([0, 14])

def autolabel(rects, textlabel):
    # attach some text labels
    idx = 0
    offset = 0
    for rect in rects:
        height = rect.get_height()
        if idx == 4:
            offset = 0.4
        elif idx == 5:
            offset = 0.3
        else:
            offset = 0.05
        offset = 0.05
        ax.text(rect.get_x() + rect.get_width()/1.9, offset + height,
                '%s' % textlabel[idx],
                ha='center', va='bottom', fontsize=17)
        idx += 1

pct = baseline_fps/baseline_fps*100
baseline_pct = ["{0}%".format(str(round(x, 1) if x % 1 else int(x))) for x in pct]
#autolabel(rects1, baseline_pct)
pct = fps/baseline_fps*100
src_pct = ["{0}%".format(str(round(x, 1) if x % 1 else int(x))) for x in pct]
src_pct = ["%d%%" % x for x in pct]
autolabel(rects2, src_pct)

pos = [2, 1.2, 1, 0.3, 0.17, 0.02, 0.7]

def autolabelvert (rects, textlabel):
    # attach some text labels
    idx = 0
    for rect in rects:
        height = rect.get_height()
        if idx == 3 or idx == 2 or idx==4 or idx==5 or idx==6:
            ax.text(rect.get_x() + rect.get_width()/2, pos[idx],
                    '%s Gbps' % textlabel[idx],
                    ha='center', va='bottom', fontsize=13)
                    #ha='center', va='bottom', fontsize=12, fontweight='bold')
        else:
            ax.text(rect.get_x() + rect.get_width()/2, pos[idx],
                    '%s Gbps' % textlabel[idx],
                    ha='center', va='bottom', fontsize=13, rotation='vertical')
                    #ha='center', va='bottom', fontsize=12, rotation='vertical', fontweight='bold')
        idx += 1

#lbl = ["%.2f" % x for x in baseline_bps]
#autolabelvert(rects1, lbl)
lbl = ["%.2f" % x for x in bps]
#autolabelvert(rects2, lbl)

fig1 = plt.gcf()
w, h = mpl.figure.figaspect(0.56)
fig1.set_size_inches(w, h)
#plt.show()
fig1.savefig('ipsec_throughput.eps', format='eps', dpi=1200)
