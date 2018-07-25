#!/usr/bin/env python
# a bar plot with errorbars
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt

mpl.rcParams['pdf.fonttype'] = 42
N = 4

pkt_size = np.array([64., 128., 256., 64.*7/12 + 594.*4/12 + 1518.*1/12])
#pkt_size += (8 + 12) # Preamble (8 bytes), Inter-frame gap (12 bytes)
pkt_size *= 8
pkt_size /= 1000

# 64, 128, 256, iMix
baseline_fps = np.array ([14.88, 8.45, 4.53, 3.29])

prefix16_fps = np.array ([11.01, 8.45, 4.53, 3.29])
prefix16_bps = prefix16_fps*pkt_size

prefix8_fps = np.array ([10.9, 8.45, 4.53, 3.29])
prefix8_bps = prefix8_fps*pkt_size

mix_fps = np.array ([8.13, 8.1, 4.53, 3.29])
mix_bps = mix_fps*pkt_size

ind = np.arange(0, N)  # the x locations for the groups
margin = 0.1
width = 0.28     # the width of the bars
offset = 0.03   #spacing between columns

colors = ['#edf8fb', '#b3cde3', '#8c96c6', '#88419d']
colors = ['#fed98e', '#bae4bc', '#7bccc4', '#2b8cbe']
#colors = ['#b2e2e2', '#edf7ff', '#acd9bb', '#d9bfdb']
colors = ['#80cdc1', '#f5f5f5', '#dfc27d', '#a6611a']
#colors = ['#fdae61',
#'#ffffbf',
#'#abd9e9',
#'#2c7bb6']
colors = ['#c2a5cf',
'#f7f7f7',
'#a6dba0',
'#008837']
fig, ax = plt.subplots()
#ax.bar(ind-margin*0.4, baseline_fps, width*3+offset*2+margin*0.8, color=colors[0], zorder=3)
rects0 = ax.bar(ind-margin*0.3, baseline_fps, width*3+offset*2+margin*0.6, color=colors[0], zorder=3, edgecolor=colors[0])
rects1 = ax.bar(ind, prefix16_fps, width, color=colors[1], zorder=3)
rects2 = ax.bar(ind + width + offset, prefix8_fps, width, color=colors[2], zorder=3)
rects3 = ax.bar(ind + (width + offset)*2, mix_fps, width, color=colors[3], zorder=3)

# add some text for labels, title and axes ticks
ax.set_ylabel('Throughput (Mpps)', fontsize=24)
#ax.set_title('Scores by group and gender')
ax.set_xticks(ind + width*1.56)
ax.set_xticklabels(('64 B', '128 B', '256 B', 'iMIX'), fontsize=24)
#ax.set_xticklabels(('70 B', '128 B', '256 B', '512 B', 'iMix'), fontsize=28)
ax.margins(0.08, 0)
ax.yaxis.grid(True,zorder=0, color='#dedede', linestyle='-')

ax.legend((rects0[0], rects1[0], rects2[0], rects3[0]), ('Baseline', '2$^{16}$ addr. in one /16 prefix', '2$^{24}$ addr. in one /8 prefix', '2$^{26}$ addr. in 4401 disjoint prefixes'), fontsize=20)
plt.yticks(np.arange(0, 20, 2))
plt.tick_params(axis='y', which='major', labelsize=24)

ax.set_xlim([-margin, ind[-1]+width*3+offset*2+margin])
ax.set_ylim([0, 18])

def autolabel(rects, textlabel):
    # attach some text labels
    idx = 0
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()/1.75, 0.12 + height,
                '%s' % textlabel[idx],
                ha='center', va='bottom', fontsize=16)
        idx += 1

pct = prefix16_fps/baseline_fps*100
prefix16_pct_str = ["{0}%".format(str(round(x, 1) if x % 1 else int(x))) for x in pct]
prefix16_pct_str = [("%d%%" % (x)) for x in pct]
autolabel(rects1, prefix16_pct_str)

pct = prefix8_fps/baseline_fps*100
prefix8_pct_str = ["{0}%".format(str(round(x, 1) if x % 1 else int(x))) for x in pct]
prefix8_pct_str = [("%d%%" % (x)) for x in pct]
autolabel(rects2, prefix8_pct_str)

pct = mix_fps/baseline_fps*100
mix_pct_str = ["{0}%".format(str(round(x, 1) if x % 1 else int(x))) for x in pct]
mix_pct_str = [("%d%%" % (x)) for x in pct]
autolabel(rects3, mix_pct_str)

def autolabelvert (rects, textlabel):
    # attach some text labels
    idx = 0
    for rect in rects:
        height = rect.get_height()
        if idx == 3 or idx == 2:
            ax.text(rect.get_x() + rect.get_width()/2.1, 1.1,
                    '%s\nGbps' % textlabel[idx],
                    ha='center', va='bottom', fontsize=14)
                    #ha='center', va='bottom', fontsize=12, fontweight='bold')
        else:
            ax.text(rect.get_x() + rect.get_width()/1.89, 2.5,
                    '%s Gbps' % textlabel[idx],
                    ha='center', va='bottom', fontsize=14, rotation='vertical')
                    #ha='center', va='bottom', fontsize=12, rotation='vertical', fontweight='bold')
        idx += 1

#lbl = ["%.2f" % x for x in prefix16_bps]
#autolabelvert(rects1, lbl)
#lbl = ["%.2f" % x for x in prefix8_bps]
#autolabelvert(rects2, lbl)
#lbl = ["%.2f" % x for x in mix_bps]
#autolabelvert(rects3, lbl)


fig1 = plt.gcf()
w, h = mpl.figure.figaspect(0.56)
fig1.set_size_inches(w, h)
#plt.show()
fig1.savefig('nat_throughput.eps', format='eps', dpi=1200)
