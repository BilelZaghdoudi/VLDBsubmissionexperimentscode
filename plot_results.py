"""
plot_results.py

Builds the evaluation figures of the VERDICT paper (Section 7) from the CSV
files produced by run_experiments.py.

Each point is the mean over all repetitions of a configuration; error bars are
95% confidence intervals (Student t). Figures are sized for one column of the
PVLDB two-column layout and written as vector PDF (for the paper) and PNG.
If a LaTeX installation is available, text is typeset with the Linux
Libertine font used by the paper; otherwise a generic serif font is used.

Usage:
    python plot_results.py --results results --figures figures
"""
import argparse
import shutil
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter, MaxNLocator
from scipy import stats

# Okabe-Ito colour-blind-safe palette, as in the original figures
DATA = dict(label="Data DAG", color="#E69F00", marker="o", linestyle="-")
EVENT = dict(label="Event DAG", color="#0072B2", marker="s", linestyle="--")
SERIES = [("data", DATA), ("event", EVENT)]

WIDTH, HEIGHT = 3.33, 1.55   # inches: one PVLDB column


def setup_style(use_tex: bool):
    rc = {
        "font.size": 8,
        "axes.labelsize": 8.5,
        "axes.titlesize": 8.5,
        "legend.fontsize": 7.5,
        "xtick.labelsize": 7.5,
        "ytick.labelsize": 7.5,
        "axes.linewidth": 0.6,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.linestyle": ":",
        "grid.linewidth": 0.5,
        "grid.color": "#b0b0b0",
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "xtick.major.size": 2.5,
        "ytick.major.size": 2.5,
        "xtick.direction": "out",
        "ytick.direction": "out",
        "lines.linewidth": 1.2,
        "lines.markersize": 3.6,
        "errorbar.capsize": 1.8,
        "legend.frameon": False,
        "legend.handlelength": 2.4,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
        "pdf.fonttype": 42,
    }
    if use_tex:
        rc.update({"text.usetex": True, "font.family": "serif",
                   "text.latex.preamble": r"\usepackage{libertine}\usepackage[libertine]{newtxmath}"})
    else:
        rc.update({"font.family": "serif", "font.serif": ["Linux Libertine O", "Libertinus Serif",
                                                          "DejaVu Serif"]})
    plt.rcParams.update(rc)


def mean_ci(values):
    v = np.asarray(values, dtype=float)
    m = v.mean()
    if len(v) < 2:
        return m, 0.0
    return m, stats.t.ppf(0.975, len(v) - 1) * v.std(ddof=1) / np.sqrt(len(v))


def aggregate(df, x, y, bins=None):
    """Mean and 95% CI of y for each value (or bin) of x."""
    key = df[x] if bins is None else pd.cut(df[x], bins)
    rows = []
    for k, grp in df.groupby(key, observed=True):
        if grp.empty:
            continue
        m, ci = mean_ci(grp[y])
        xv = grp[x].mean() if bins is not None else k
        rows.append((xv, m, ci))
    return pd.DataFrame(rows, columns=["x", "mean", "ci"]).sort_values("x")


def kilo(x, _pos):
    return f"{x / 1000:g}k" if x >= 1000 else f"{x:g}"


def new_axes():
    fig, ax = plt.subplots(figsize=(WIDTH, HEIGHT))
    return fig, ax


def draw(ax, agg, style, scale=1.0, hollow=False, zorder=3):
    kw = dict(style)
    if hollow:
        kw.update(markerfacecolor="white", markeredgewidth=0.9)
    ax.errorbar(agg["x"], agg["mean"] * scale, yerr=agg["ci"] * scale, elinewidth=0.7,
                capthick=0.7, zorder=zorder, **kw)


NODE_TICKS = [1000, 5000, 10000, 15000, 20000]


def finish(fig, ax, xlabel, ylabel, out: Path, kx=False, ymin0=True, legend_loc="best", xticks=None):
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if kx:
        ax.set_xticks(NODE_TICKS)
        ax.xaxis.set_major_formatter(FuncFormatter(kilo))
    elif xticks is not None:
        ax.set_xticks(xticks)
    ax.yaxis.set_major_locator(MaxNLocator(nbins=6))
    if ymin0:
        ax.set_ylim(bottom=0, top=ax.get_ylim()[1] * 1.08)
    ax.legend(loc=legend_loc)
    fig.savefig(out.with_suffix(".pdf"))
    fig.savefig(out.with_suffix(".png"), dpi=300)
    plt.close(fig)
    print(f"  wrote {out.with_suffix('.pdf')} (+ .png)")


def per_dag_plot(df, x, ytmpl, xlabel, ylabel, out, scale=1.0, kx=False, legend_loc="best"):
    if df.empty:
        return
    fig, ax = new_axes()
    for prefix, style in SERIES:
        draw(ax, aggregate(df, x, ytmpl.format(prefix)), style, scale)
    finish(fig, ax, xlabel, ylabel, out, kx=kx, legend_loc=legend_loc,
           xticks=None if kx else sorted(df[x].unique()))


def load(results: Path, experiment: str) -> pd.DataFrame:
    path = results / experiment / "evaluation_log.csv"
    if not path.exists():
        print(f"  (missing {path}, skipped)")
        return pd.DataFrame()
    return pd.read_csv(path)


def main():
    parser = argparse.ArgumentParser(description="Plot VERDICT evaluation results")
    parser.add_argument("--results", default="results")
    parser.add_argument("--figures", default="figures")
    parser.add_argument("--no-tex", action="store_true", help="Do not use LaTeX for text rendering")
    args = parser.parse_args()

    setup_style(use_tex=not args.no_tex and shutil.which("latex") is not None)
    results, figs = Path(args.results), Path(args.figures)
    figs.mkdir(parents=True, exist_ok=True)

    nodes = load(results, "nodes")
    if not nodes.empty:
        # Fig. 1: diversity is a deterministic function of the number of levels,
        # hence of the skip-edge count; both DAGs have the same number of levels.
        fig, ax = new_axes()
        for prefix, style, hollow in (("data", DATA, False), ("event", EVENT, True)):
            d = nodes[[f"{prefix}_skip_edges", f"{prefix}_skip_diversity"]].drop_duplicates()
            d = d.sort_values(f"{prefix}_skip_edges")
            kw = dict(style)
            if hollow:
                kw.update(markerfacecolor="white", markeredgewidth=0.9, linestyle="none", markersize=4.4)
            ax.plot(d.iloc[:, 0], d.iloc[:, 1], **kw)
        finish(fig, ax, "Number of skip edges", "Skip DAG diversity (bits)",
               figs / "fig1_skip_diversity_vs_skip_edges", ymin0=False, legend_loc="lower right")

        # Fig. 10 (technical report): diversity vs. number of nodes.
        fig, ax = new_axes()
        for prefix, style, hollow in (("data", DATA, False), ("event", EVENT, True)):
            draw(ax, aggregate(nodes, "nodes", f"{prefix}_skip_diversity"), style, hollow=hollow)
        finish(fig, ax, "Number of nodes", "Skip DAG diversity (bits)",
               figs / "fig10_skip_diversity_vs_nodes", kx=True, ymin0=False, legend_loc="lower right")

        per_dag_plot(nodes, "nodes", "{}_skip_dag_time_ms", "Number of nodes", "Construction time (s)",
                     figs / "fig2_skip_construction_vs_nodes", scale=1e-3, kx=True, legend_loc="upper left")

        bins = np.arange(180, 600, 40)
        fig, ax = new_axes()
        for prefix, style in SERIES:
            draw(ax, aggregate(nodes, f"{prefix}_skip_edges", f"avg_{prefix}_skip_search_time_ms", bins),
                 style, scale=1e3)
        finish(fig, ax, "Number of skip edges", r"Search time ($\mu$s)" if plt.rcParams["text.usetex"]
               else "Search time (µs)", figs / "fig4_skip_search_vs_skip_edges", legend_loc="lower right")

        per_dag_plot(nodes, "nodes", "{}_verification_time_ms", "Number of nodes", "Verification time (ms)",
                     figs / "fig5_skip_verification_vs_nodes", kx=True, legend_loc="lower right")
        per_dag_plot(nodes, "nodes", "{}_merkle_time_ms", "Number of nodes", "Construction time (ms)",
                     figs / "fig6_merkle_construction_vs_nodes", kx=True, legend_loc="upper left")
        per_dag_plot(nodes, "nodes", "{}_merkle_verification_time_ms", "Number of nodes",
                     "Verification time (ms)", figs / "fig7_merkle_verification_vs_nodes", kx=True,
                     legend_loc="lower right")

    genesis = load(results, "genesis")
    per_dag_plot(genesis, "genesis", "{}_verification_time_ms", "Number of genesis nodes",
                 "Verification time (ms)", figs / "fig8_verification_vs_genesis", legend_loc="lower right")

    edges = load(results, "edges")
    per_dag_plot(edges, "edges", "{}_verification_time_ms", "Maximum number of edges per node",
                 "Verification time (ms)", figs / "fig9_verification_vs_edges", legend_loc="lower right")

    ins_files = sorted((results / "insertion").glob("skip_insertion_eval_detailed_results_*.csv"))
    if ins_files:
        ins = pd.concat([pd.read_csv(f).assign(nodes=int(f.stem.rsplit("_", 1)[-1])) for f in ins_files])
        fig, ax = new_axes()
        draw(ax, aggregate(ins[ins["dag_type"] == "Data"], "nodes", "insertion_time_ms"), DATA)
        finish(fig, ax, "Number of nodes", "Insertion time (ms)", figs / "fig3_skip_insertion_vs_nodes",
               kx=True, legend_loc="lower right")
    else:
        print("  (no insertion results, Fig. 3 skipped)")


if __name__ == "__main__":
    main()
