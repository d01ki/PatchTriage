"""The single-page GUI. Self-contained: inline CSS + JS, no external assets."""

import json

from ..ssvc import (
    HumanImpact,
    MissionImpact,
    SafetyImpact,
    SystemExposure,
    derive_human_impact,
    label_for,
)


def _human_impact_matrix() -> dict[str, str]:
    """Serialize the official Human Impact table for the form preview.

    Generated from the engine rather than retyped in JavaScript: the preview
    under the Mission and Safety questions must show the same value the
    deterministic backend will produce.
    """
    return {
        f"{safety.value}|{mission.value}": derive_human_impact(
            mission, safety).value
        for safety in SafetyImpact
        for mission in MissionImpact
    }


def _decision_point_labels() -> dict[str, str]:
    """Official value labels the form renders, keyed by stored value."""
    return {
        value.value: label_for(value.value)
        for group in (SystemExposure, MissionImpact, SafetyImpact, HumanImpact)
        for value in group
    }


_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#060a13">
<title>PatchTriage</title>
<style>
  :root{
    --void:#090c12;--void2:#10141e;--panel:#151a25;--panel2:#1b2130;
    --ink:#f4f6fb;--muted:#929cad;--line:#2a3243;--hot:#ff4d3d;
    --amber:#ffb020;--blue:#6e8cff;--cyan:#49d6e9;--paper:#eef1f7;
    --dark:#171b25;--immediate:#ff4d3d;--outofcycle:#ffb020;--scheduled:#6e8cff;--defer:#778195;
  }
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{margin:0;background:var(--void);color:var(--ink);
    font:16px/1.58 Inter,"Segoe UI",Helvetica,Arial,sans-serif}
  button,input,select{font:inherit}button{cursor:pointer}
  a{color:inherit}.mono{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace}
  .topbar{height:58px;padding:0 clamp(20px,4vw,64px);display:flex;align-items:center;
    justify-content:space-between;border-bottom:1px solid var(--line);background:rgba(9,12,18,.96);
    position:sticky;top:0;z-index:20}
  .brand{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:.08em}
  .brandmark{width:27px;height:27px;border:2px solid var(--hot);position:relative}
  .brandmark:before,.brandmark:after{content:"";position:absolute;background:var(--hot)}
  .brandmark:before{width:13px;height:2px;left:5px;top:7px}.brandmark:after{width:2px;height:13px;left:11px;top:5px}
  .brand span{color:var(--hot)}
  .statusdot{width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 12px var(--cyan)}
  .hero{max-width:1500px;margin:0 auto;padding:clamp(16px,2.2vw,30px) clamp(20px,4vw,64px) 30px;
    display:grid;grid-template-columns:minmax(340px,.95fr) minmax(520px,1.2fr);gap:clamp(36px,6vw,90px);align-items:center}
  .eyebrow{color:var(--hot);font:700 13px/1.2 "SFMono-Regular",Consolas,monospace;letter-spacing:.16em;text-transform:uppercase}
  h1{font-size:clamp(42px,5.7vw,78px);line-height:.97;letter-spacing:-.052em;margin:12px 0 20px;max-width:780px}
  h1 em{font-style:normal;color:var(--hot)}
  .hero p{color:#b3bccb;font-size:clamp(17px,1.55vw,21px);max-width:680px;margin:0 0 25px}
  .heroactions{display:flex;gap:12px;flex-wrap:wrap}
  .btn{border:1px solid var(--line);border-radius:5px;padding:10px 15px;background:var(--panel2);color:var(--ink);font-weight:650}
  .btn:hover{border-color:#526078}.btn:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
  .btn.primary{background:var(--hot);border-color:var(--hot);color:#fff;box-shadow:0 8px 32px rgba(255,77,61,.2)}
  .btn.primary:hover{background:#ff6255}.btn.ghost{background:transparent}.btn.small{padding:7px 11px;font-size:13px}
  .btn.danger{color:#ff8a80;background:transparent}.btn:disabled{opacity:.45;cursor:not-allowed}
  .proof{border:1px solid var(--line);background:var(--s1);padding:24px;position:relative;overflow:hidden}
  .proof:after{content:"";position:absolute;width:180px;height:180px;border-radius:50%;background:var(--hot);filter:blur(100px);opacity:.12;right:-60px;top:-60px}
  .proofhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;color:var(--muted);font:12px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;letter-spacing:.1em}
  .flow{display:grid;grid-template-columns:1fr 26px 1fr 26px 1fr;align-items:stretch;gap:5px}
  .node{border:1px solid var(--line);background:var(--panel);padding:16px 14px;min-height:118px}
  .node strong{display:block;font-size:15px;margin:8px 0 5px}.node small{color:var(--muted);font-size:12.5px;display:block}
  .nodecode{color:var(--cyan);font:700 12px "SFMono-Regular",Consolas,monospace}
  .arrow{display:flex;align-items:center;justify-content:center;color:#59667a;font-size:22px}
  .decision{grid-column:1/-1;margin-top:12px;border-left:3px solid var(--hot);background:#1c171c;padding:16px 18px;display:flex;justify-content:space-between;gap:20px;align-items:center}
  .decision b{font-size:18px}.decision span{color:var(--muted);font-size:12px}.decision .outcome-now{text-align:right;font:800 22px "SFMono-Regular",Consolas,monospace;color:var(--hot)}
  .benchmark{max-width:1500px;margin:0 auto 34px;padding:0 clamp(20px,4vw,64px);display:grid;grid-template-columns:minmax(300px,.9fr) minmax(520px,1.35fr);gap:1px}
  .benchmarkcopy{background:#111722;border:1px solid var(--line);padding:24px}.benchmarkcopy h2{font-size:clamp(23px,2.8vw,36px);line-height:1.08;letter-spacing:-.035em;margin:10px 0}.benchmarkcopy p{color:var(--muted);margin:0;font-size:13.5px}
  .outcomes{display:grid;grid-template-columns:repeat(4,1fr)}.outcome{background:var(--panel);border:1px solid var(--line);border-left:0;padding:20px 18px}.factorcode{display:inline-flex;color:var(--cyan);border:1px solid #325464;border-radius:20px;padding:3px 7px;font:750 10.5px/1.2 "SFMono-Regular",Consolas,monospace;letter-spacing:.06em;text-transform:uppercase}.outcome strong{display:block;color:var(--ink);font-size:19px;line-height:1.2;margin:12px 0 4px}.factorquestion{display:block;color:#d2d8e3;font-size:13.5px;font-weight:650;line-height:1.35;min-height:37px}.outcome small{display:block;color:var(--muted);font-size:12.5px;line-height:1.45;margin-top:8px}.outcome small b{color:#c8cfdb;font-weight:700}
  .kpis{max-width:1500px;margin:0 auto;padding:0 clamp(20px,4vw,64px) 34px;display:grid;grid-template-columns:repeat(4,1fr);gap:1px}
  .kpi{background:var(--panel);border:1px solid var(--line);padding:15px 18px}.kpi+.kpi{border-left:0}
  .kpi .value{font:750 28px "SFMono-Regular",Consolas,monospace}.kpi .label{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.07em}
  .workspace{background:var(--paper);color:var(--dark);border-radius:22px 22px 0 0;min-height:720px;padding:34px clamp(20px,4vw,64px) 70px}
  .workspaceinner{max-width:1500px;margin:0 auto;display:grid;grid-template-columns:minmax(0,1fr);gap:30px}
  .sectiontitle{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:14px}
  .sectiontitle h2{margin:0;font-size:22px;letter-spacing:-.02em}.sectiontitle span{font:13px "SFMono-Regular",Consolas,monospace;color:#70798a;text-transform:uppercase;letter-spacing:.07em}
  .decisionactions{display:flex;align-items:center;gap:8px}.enginecontrol{display:grid;gap:2px;min-width:190px}.enginelabel{color:#70798a;font:700 10.5px/1.2 "SFMono-Regular",Consolas,monospace;letter-spacing:.07em;text-transform:uppercase}.enginevalue{border:1px solid #cfd5e2;border-radius:5px;background:#f7f8fb;color:#313a49;padding:7px 10px;font-size:13px;line-height:1.2}.enginecontrol select{width:auto;min-width:190px;padding:6px 9px;font-size:13px}
  .prioritylegend{display:grid;grid-template-columns:repeat(4,1fr);margin-bottom:14px;overflow:hidden}.prioritylegend>div{padding:11px 12px;border-right:1px solid #e2e6ee;font-size:13px;color:#687285;line-height:1.45}.prioritylegend>div:last-child{border-right:0}.prioritylegend b{display:block;font-size:14px;color:#2d3441}.prioritylegend i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;background:var(--defer)}.prioritylegend .immediate i{background:var(--immediate)}.prioritylegend .outofcycle i{background:var(--outofcycle)}.prioritylegend .scheduled i{background:var(--scheduled)}
  .lightpanel{background:#fff;border:1px solid #d9deea;border-radius:10px;box-shadow:0 10px 28px rgba(30,40,65,.06)}
  details.add{margin-bottom:14px}details.add>summary{list-style:none;padding:14px 16px;font-weight:700;cursor:pointer;display:flex;justify-content:space-between}
  details.add>summary::-webkit-details-marker{display:none}details.add>summary:after{content:"+";color:#697386}details.add[open]>summary:after{content:"−"}
  .form{border-top:1px solid #e4e7ee;padding:16px;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;align-items:start}.form>.addrow,.form>.ssvcblock,.form>.advanced,.form>.hint{grid-column:1/-1}.addhead{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;padding:14px 16px}.addhead h3{margin:0;font-size:17px}.addrow{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.4fr) auto;gap:12px;align-items:end}.addrow .formactions{display:flex;gap:8px}.ssvcblock{grid-template-columns:repeat(4,minmax(0,1fr))}.ssvcblock>.ssvchead,.ssvcblock>.ssvcabout{grid-column:1/-1}details.add,section.add{margin-bottom:14px}
  input[type=text],select{width:100%;border:1px solid #cfd5e2;border-radius:5px;padding:9px 10px;background:#fff;color:#171b25}
  .contextintro{border:1px solid #cfd7e8;background:#f7f8fc;border-radius:6px;padding:12px;display:grid;gap:7px}.contexttitle{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.contexttitle strong{font-size:14px}.standardtag{display:inline-flex;border:1px solid #b9c5ed;border-radius:20px;background:#edf1ff;color:#3048a8;padding:3px 7px;font:750 10px/1.2 "SFMono-Regular",Consolas,monospace;letter-spacing:.04em;text-transform:uppercase}.contextintro span,.contextintro a{font-size:13px;color:#667183;line-height:1.45}.contextintro a{color:#4053ba;font-weight:700;text-decoration:none}.contextintro a:hover{text-decoration:underline}.patchtriagenote{border-left:3px solid #e6a32d;background:#fff8e8;padding:8px 9px;color:#66502b!important}.patchtriagenote b{color:#5a4015}
  .fieldlabel{display:grid;gap:5px;color:#697386;font-size:13px;font-weight:750;text-transform:uppercase;letter-spacing:.045em}.fieldtitle{display:flex;align-items:center;justify-content:space-between;gap:7px}.fieldlabel select,.fieldlabel input{font-size:14px;text-transform:none;letter-spacing:0}.fieldhelp{color:#70798a;font-size:12.5px;font-weight:500;text-transform:none;letter-spacing:0;line-height:1.45}.fieldhelp b{color:#4f596a}.formactions{display:flex;gap:7px}.formactions .btn{flex:1}
  .ssvcblock{border:1px solid #cfd7e8;background:#f6f8fd;border-radius:8px;padding:12px;display:grid;gap:10px}
  .ssvchead{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}.ssvchead>div{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.ssvchead strong{font-size:14px}
  .ssvcprogress{font:750 10px/1.2 "SFMono-Regular",Consolas,monospace;letter-spacing:.04em;text-transform:uppercase;color:#8a6412;background:#fff3d8;border:1px solid #e8cf94;border-radius:20px;padding:4px 8px;white-space:nowrap}
  .ssvcprogress.done{color:#1c6b45;background:#e6f6ee;border-color:#a4d8bf}
  .ssvcabout{font-size:12.5px;color:#667183}.ssvcabout>summary{cursor:pointer;font-weight:750;color:#4053ba;list-style:none}.ssvcabout>summary::-webkit-details-marker{display:none}.ssvcabout>summary:before{content:"? ";font-weight:800}.ssvcabout .aboutbody{display:grid;gap:6px;margin-top:7px;line-height:1.5}.ssvcabout a{color:#4053ba;font-weight:700;text-decoration:none}.ssvcabout a:hover{text-decoration:underline}
  .ssvcfield{background:#fff;border:1px solid #dde3f0;border-left:3px solid #dde3f0;border-radius:7px;padding:10px 11px;display:grid;gap:7px}
  .ssvcfield.pending{border-left-color:#e6a32d}.ssvcfield.set{border-left-color:#4053ba}
  .fieldhead{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
  .fieldnum{flex:none;width:19px;height:19px;border-radius:50%;background:#39456b;color:#fff;font:750 11px/19px "SFMono-Regular",Consolas,monospace;text-align:center}
  .ssvcfield.set .fieldnum{background:#4053ba}
  .fieldname{font-weight:800;font-size:14px;color:#232a3a;letter-spacing:-.01em}
  .fieldq{margin:0;font-size:12.5px;color:#69738a;line-height:1.5}
  .fieldnow{font-size:12.5px;line-height:1.5;color:#5b6577;border-left:2px solid #e2e7f2;padding-left:9px}.fieldnow b{color:#232a3a}
  .fieldnow.fallback{border:1px solid #e8cf94;border-left:3px solid #e6a32d;background:#fff8e8;color:#6b5324;padding:7px 9px;border-radius:0 5px 5px 0}.fieldnow.fallback b{color:#5a4015}
  .derived{border:1px dashed #b9c5ed;background:#fff;border-radius:7px;padding:10px 11px;display:grid;gap:6px}
  .derivedlabel{display:flex;align-items:center;gap:7px;flex-wrap:wrap;font:750 10px/1.2 "SFMono-Regular",Consolas,monospace;letter-spacing:.05em;text-transform:uppercase;color:#4053ba}
  .derivedvalue{display:flex;align-items:baseline;gap:9px;flex-wrap:wrap}.derivedvalue b{font-size:19px;color:#232a3a;letter-spacing:-.01em}.derivedvalue span{font-size:12.5px;color:#69738a}
  .derivednote{font-size:12px;color:#78819a;line-height:1.5}

  .hint{font-size:13.5px;color:#70798a;line-height:1.45}.targetlist{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
  .privacy{border:1px solid #efc46d;background:#fff7e2;color:#725016;border-radius:6px;padding:10px 11px;font-size:12.5px;line-height:1.45}
  .advanced{border:1px solid #dbe0ec;border-radius:6px;padding:8px 10px}.advanced summary{cursor:pointer;font-weight:750;color:#596579;font-size:13px;display:flex;justify-content:space-between}.advanced summary:after{content:"+"}.advanced[open] summary:after{content:"−"}.advcols{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,3fr);gap:16px;margin-top:10px}.advcol{display:grid;gap:8px;align-content:start;min-width:0}.advcol+.advcol{border-left:1px solid #e6e9f1;padding-left:16px}.advgroup{font-weight:750;font-size:13px;color:#29344a}.advfields{display:grid;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:8px;align-items:end}.advfields select,.advfields input{width:100%;min-width:0}
  .target{background:#fff;border:1px solid #d9deea;border-radius:8px;padding:13px;transition:.18s}
  .target:hover{border-color:#b8c1d3;transform:translateY(-1px)}.targettop{display:flex;justify-content:space-between;gap:8px}
  .targetname{font-weight:750;overflow-wrap:anywhere}.targetname a{text-decoration:none}.targetname a:hover{text-decoration:underline}
  .targetid{font:12px "SFMono-Regular",Consolas,monospace;color:#858e9d;margin-top:2px}
  .badges{display:flex;gap:5px;flex-wrap:wrap;margin-top:9px}.tag{font:700 11.5px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;letter-spacing:.035em;border:1px solid #d5dae5;border-radius:20px;padding:4px 7px;color:#5c6575;background:#f7f8fb}
  .tag.hot{color:#c93025;background:#fff0ee;border-color:#ffd0ca}.tag.demo{color:#674100;background:#fff4d8;border-color:#ffdfa0}.tag.warn{color:#8a5700;background:#fff5dc;border-color:#f5d487}
  .source{font-size:12px;color:#6f7888;margin:9px 0;line-height:1.4}.source.ready{color:#354fd1}.targetactions{display:flex;gap:6px;flex-wrap:wrap}.btn.attach{background:#eef1ff;color:#3048c5;border-color:#bec7f5}
  .results{display:flex;flex-direction:column;gap:14px}.empty{min-height:390px;display:grid;grid-template-columns:1fr 1fr;overflow:hidden}
  .emptycopy{padding:clamp(28px,4vw,54px);display:flex;flex-direction:column;justify-content:center}.emptycopy .eyebrow{color:#5563d8}.emptycopy h3{font-size:clamp(28px,3.3vw,46px);line-height:1.04;letter-spacing:-.045em;margin:13px 0}.emptycopy p{color:#687285;max-width:50ch}
  .emptyviz{background:#121722;color:#fff;padding:32px;display:flex;flex-direction:column;justify-content:center}.versus{display:grid;grid-template-columns:1fr auto 1fr;gap:14px;align-items:center}.method{border:1px solid #30394b;padding:17px}.method strong{display:block;font-size:22px}.method small{color:#929cad}.method.miss strong{color:var(--hot)}.method.hit{border-color:#566cf0}.method.hit strong{color:#9eb0ff}.vs{font:700 11px "SFMono-Regular",Consolas,monospace;color:#667084}
  .result{background:#fff;border:1px solid #d7dce7;border-radius:10px;overflow:hidden;box-shadow:0 12px 35px rgba(30,40,65,.07)}
  .resulthead{display:grid;grid-template-columns:154px 1fr auto;gap:17px;align-items:center;padding:19px 21px;border-bottom:1px solid #e2e6ee}
  .prioritybox{min-width:0}.prioritymeaning{text-align:center;color:#586274;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.055em;margin-top:5px}.prioritydue{text-align:center;color:#7b8494;font:12px "SFMono-Regular",Consolas,monospace;margin-top:2px}
  .priority{height:66px;display:flex;align-items:center;justify-content:center;text-align:center;border-radius:6px;color:white;font:850 16px "SFMono-Regular",Consolas,monospace;background:var(--defer);padding:8px}
  .priority.immediate{background:var(--immediate)}.priority.out-of-cycle{background:var(--outofcycle);color:#2d1d00}.priority.scheduled{background:var(--scheduled)}
  .priority.no-findings{background:#6f7888}.rname{font-size:13px;color:#737d8d;margin-bottom:4px}.action{font-size:21px;font-weight:780;line-height:1.2;letter-spacing:-.025em}.reportlink{text-decoration:none;color:#3048c5;font-weight:700;font-size:13px;white-space:nowrap}
  .metricrow{padding:12px 21px;display:flex;gap:7px;flex-wrap:wrap;background:#fafbfc;border-bottom:1px solid #e5e8ef}.metric{font:12.5px "SFMono-Regular",Consolas,monospace;background:#edf0f5;border-radius:4px;padding:5px 8px;color:#4f5969}.metric.alert{background:#ffebe8;color:#c42f24}.metric.audit{background:#e8f9fc;color:#226976}
  .resultbody{display:grid;grid-template-columns:minmax(320px,.85fr) minmax(430px,1.15fr);gap:0}.compare{padding:21px;border-right:1px solid #e4e7ed}.explain{padding:21px}
  .microtitle{font:750 12px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;letter-spacing:.1em;color:#6f798a;margin-bottom:12px}
  .barrow{display:grid;grid-template-columns:104px 1fr 46px;gap:9px;align-items:center;margin:10px 0;font-size:13px}.track{height:8px;background:#e7eaf0;border-radius:2px;overflow:hidden}.fill{height:100%;background:#a7afbd}.fill.epss{background:#6f7f99}.fill.pt{background:#5368e8}.barvalue{font:700 13px "SFMono-Regular",Consolas,monospace;text-align:right}
  .outcomegrid{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:14px}.outcomemicro{border:1px solid #dfe3eb;background:#f8f9fb;border-radius:5px;padding:10px}.outcomemicro b{display:block;color:#344ac8;font:800 19px "SFMono-Regular",Consolas,monospace}.outcomemicro span{font-size:11.5px;color:#687285;text-transform:uppercase;letter-spacing:.035em}
  .comparefoot{font-size:13.5px;color:#687285;margin-top:13px}.basis{border-left:3px solid #5368e8;background:#f0f2ff;color:#27336f;border-radius:3px;padding:11px 12px;margin-bottom:11px;font-size:14px;font-weight:650}.ssvcflow{display:grid;grid-template-columns:repeat(4,1fr);gap:5px;align-items:stretch}.factor{border:1px solid #dfe3eb;background:#f8f9fb;border-radius:5px;padding:10px}.factor span{font:11.5px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;color:#737d8d}.factor b{display:block;font-size:14px;margin-top:4px}.factor small{display:block;color:#737d8d;font-size:12px;margin-top:3px}.decisionline{margin-top:10px;background:#171d29;color:white;padding:11px 13px;border-radius:5px;display:flex;justify-content:space-between;align-items:center}.decisionline span{color:#a8b1c0;font-size:12.5px;text-transform:uppercase;letter-spacing:.07em}.decisionline b{color:#9aabff;font:800 17px "SFMono-Regular",Consolas,monospace}.decisionnote{margin-top:9px;border:1px solid #d8deeb;background:#f8f9fc;color:#566172;border-radius:5px;padding:10px 11px;font-size:13px}.decisionnote b{color:#293342}.signalgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:5px;margin-top:8px}.signal{border:1px solid #dfe3eb;border-radius:5px;padding:9px;background:#fff}.signal span{display:block;color:#6f7989;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em}.signal b{display:block;font:750 13.5px "SFMono-Regular",Consolas,monospace;margin-top:2px}.confirmbar{margin-top:9px;border:1px solid #f0cf86;background:#fff7e4;color:#765017;border-radius:5px;padding:10px 11px;font-size:13px}.emptyresult{border:1px solid #dbe0ea;background:#f8f9fb;border-radius:6px;padding:16px}.emptyresult b{display:block;font-size:16px}.emptyresult span{display:block;color:#647083;font-size:13.5px;margin-top:4px}
  .evidence{list-style:none;padding:0;margin:11px 0 0;display:grid;grid-template-columns:1fr 1fr;gap:6px}.evidence li{border:1px solid #e0e4ec;border-radius:5px;padding:9px 10px;display:grid;grid-template-columns:20px 1fr;gap:6px;align-items:start}.evidenceicon{width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#e5e8ee;color:#687386;font:800 10.5px "SFMono-Regular",Consolas,monospace}.evidenceicon.confirmed{background:#dff7eb;color:#15704a}.evidenceicon.attention{background:#fff0d6;color:#985d00}.evidence strong{display:block;font-size:13px}.evidence small{display:block;color:#687285;font-size:12px;line-height:1.4;margin-top:2px}
  .advisoryline{margin-top:9px;display:flex;gap:6px;flex-wrap:wrap}.advisoryline a,.advisoryline span{font:700 12px "SFMono-Regular",Consolas,monospace;text-decoration:none;border:1px solid #ccd3e1;background:#f7f8fb;color:#4053ba;padding:5px 8px;border-radius:4px}.advisoryline a:hover{text-decoration:underline}
  .ssvcinputreview{border-top:1px solid #e1e5ed;padding:18px 21px;background:#fbfcfe}.ssvcinputreview summary{cursor:pointer;font-weight:750;font-size:14px}.ssvcinputreview p{color:#657083;font-size:13px;margin:7px 0 12px}.ssvcinputtable{width:100%;border-collapse:collapse;font-size:13px}.ssvcinputtable th,.ssvcinputtable td{text-align:left;padding:8px;border-top:1px solid #e2e6ee;vertical-align:middle}.ssvcinputtable th{font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;color:#6f7989}.ssvcinputtable select{font-size:13px;min-width:145px;padding:7px}.inputsource{display:block;color:#778195;font-size:11.5px;margin-top:3px}.reviewflag{color:#a05d00;font-weight:750}.ssvcinputactions{display:flex;justify-content:flex-end;margin-top:12px}
  .running{padding:26px;border-left:4px solid #5368e8}.running strong{font-size:18px}.scanline{height:3px;background:#e1e5ed;margin-top:16px;overflow:hidden}.scanline:after{content:"";display:block;width:32%;height:100%;background:#5368e8;animation:scan 1s infinite ease-in-out}@keyframes scan{from{transform:translateX(-100%)}to{transform:translateX(410%)}}
  .toast{position:fixed;right:22px;bottom:22px;background:#151a25;color:#fff;border:1px solid #343d50;padding:11px 15px;border-radius:6px;box-shadow:0 12px 40px rgba(0,0,0,.28);transform:translateY(90px);opacity:0;transition:.2s;z-index:30;max-width:420px}.toast.show{transform:none;opacity:1}.toast.error{border-color:#a63d36}
  .filehidden{display:none}
  dialog{border:0;border-radius:10px;padding:0;box-shadow:0 24px 80px rgba(0,0,0,.38);width:min(560px,calc(100% - 28px));color:var(--dark)}dialog::backdrop{background:rgba(8,11,17,.7)}.dialogbody{padding:22px;display:grid;gap:12px}.dialogbody h3{margin:0}.dialogbody p{margin:0;color:#667183;font-size:13.5px}.dialogactions{display:flex;justify-content:flex-end;gap:8px}
  .bodpanel{margin-top:12px;border-top:1px dashed #cfd5e2;padding-top:10px}.bodpanel .factor small+small{margin-top:4px}.bodcell.reference b{color:#687285;font-weight:650}
  :root{--c-immediate:#b8322a;--c-outofcycle:#eaa51a;--c-scheduled:#4f6be0;--c-defer:#7d8799}
  .outcomesummary{display:grid;grid-template-columns:auto minmax(0,1fr);gap:22px;align-items:center;padding:16px 20px;margin-bottom:14px}
  .donut{display:block}.donut .seg{transition:opacity .15s}.donut:hover .seg{opacity:.55}.donut .seg:hover{opacity:1}
  .donutlabel{font:800 26px "SFMono-Regular",Consolas,monospace;fill:#1f2633}.donutsub{font:600 11px system-ui,sans-serif;fill:#6b7486;letter-spacing:.04em}
  .outcomerows{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
  .outcomerow{border:1px solid #e1e5ee;border-radius:8px;padding:10px 12px}
  .outcomerow .name{display:flex;align-items:center;gap:7px;font-weight:750;color:#2d3441;font-size:14px}
  .outcomerow .name i{width:10px;height:10px;border-radius:50%;flex:none}
  .outcomerow .count{font:800 24px "SFMono-Regular",Consolas,monospace;color:#1f2633;margin-top:4px}.outcomerow .count small{font:600 12px system-ui,sans-serif;color:#6b7486;margin-left:6px}
  .outcomerow .meaning{font-size:12.5px;color:#687285;line-height:1.4;margin-top:2px}
  .breakdown{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:12px 21px;border-bottom:1px solid #e5e8ef}
  .breakdown .chips{display:flex;gap:8px;flex-wrap:wrap}.breakdown .chip{display:flex;align-items:center;gap:6px;border:1px solid #e1e5ee;border-radius:20px;padding:4px 10px;font-size:13px;color:#2d3441}.breakdown .chip i{width:9px;height:9px;border-radius:50%}.breakdown .chip b{font-family:"SFMono-Regular",Consolas,monospace}
  .treeview{border-top:1px solid #e1e5ed;padding:18px 21px}.treeview>summary{cursor:pointer;font-weight:750;font-size:14px}
  .treepick{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}.treepick select{min-width:280px;max-width:100%}
  .treecanvas{overflow-x:auto;border:1px solid #e1e5ee;border-radius:8px;background:#fbfcfe}
  .treecanvas svg{display:block;min-width:820px;width:100%;height:auto}
  .tree .edge{fill:none;stroke:#d3d8e3;stroke-width:1.2}.tree .edge.on{stroke:#1f2633;stroke-width:2.6}
  .tree .node rect{fill:#fff;stroke:#cfd5e2;stroke-width:1}.tree .node text{font:600 12px system-ui,sans-serif;fill:#8a93a3}
  .tree .node.on rect{fill:#1f2633;stroke:#1f2633}.tree .node.on text{fill:#fff;font-weight:750}
  .tree .node.assumed rect{stroke-dasharray:4 3}.tree .node.on.assumed rect{fill:#3a4253;stroke:#eaa51a;stroke-width:2}
  .tree .leaf text{font:700 12px system-ui,sans-serif;fill:#fff}.tree .leaf.off{opacity:.35}.tree .leaf.on rect{stroke:#1f2633;stroke-width:2.5}
  .tree .colhead{font:700 11px system-ui,sans-serif;fill:#6b7486;letter-spacing:.06em;text-transform:uppercase}
  .tree .root rect{fill:#eef1ff;stroke:#5368e8}.tree .root text{fill:#27336f;font:700 12px system-ui,sans-serif}
  .pathsentence{margin:12px 0 6px;font-size:14px;line-height:1.6;color:#2d3441}.pathsentence b{white-space:nowrap}.pathsentence .src{color:#6b7486;font-size:12.5px}
  .treelegend{font-size:12.5px;color:#687285;margin-top:6px}
  .evidencelinks{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.evidencelinks a,.evidencelinks span{border:1px solid #d6dbe5;border-radius:4px;padding:3px 8px;font-size:12.5px;text-decoration:none;color:#3048c5;background:#fff}.evidencelinks span{color:#4f5969}
  @media(max-width:1100px){.ssvcblock{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.outcomerows{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}}
  @media(max-width:820px){.form{grid-template-columns:minmax(0,1fr)}.advcols{grid-template-columns:minmax(0,1fr)}.advcol+.advcol{border-left:0;padding-left:0;border-top:1px solid #e6e9f1;padding-top:12px}.addrow{grid-template-columns:minmax(0,1fr)}.ssvcblock{grid-template-columns:minmax(0,1fr)}.outcomesummary{grid-template-columns:minmax(0,1fr);justify-items:center}.outcomerows{width:100%}}
  .reportlinks{display:grid;gap:6px;justify-items:end}
  .statecard{padding:16px 21px;display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap}.statecard.failed{border-left:4px solid var(--immediate)}.statecard.running{border-left:4px solid var(--scheduled)}.statecard strong{display:block;font-size:15px}.statecard span{display:block;color:#647083;font-size:13.5px;margin-top:3px;overflow-wrap:anywhere}
  .actionqueue{border-top:1px solid #e1e5ed;padding:18px 21px}.actionqueue summary{cursor:pointer;font-weight:750;font-size:14px}.actionqueue p{color:#657083;font-size:13px;margin:7px 0 10px}.queuetable{width:100%;border-collapse:collapse;font-size:13px}.queuetable th,.queuetable td{text-align:left;padding:8px;border-top:1px solid #e2e6ee;vertical-align:top}.queuetable th{font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;color:#6f7989}.queuetable td.num{white-space:nowrap;font-family:"SFMono-Regular",Consolas,monospace}.queuetable .cves{display:block;color:#778195;font-size:11.5px;margin-top:3px;overflow-wrap:anywhere}.outcomepill{display:inline-flex;align-items:center;gap:6px;font-weight:750;white-space:nowrap}.outcomepill i{width:8px;height:8px;border-radius:50%;background:var(--defer)}.outcomepill.immediate i{background:var(--c-immediate)}.outcomepill.out-of-cycle i{background:var(--c-outofcycle)}.outcomepill.scheduled i{background:var(--c-scheduled)}.outcomepill i{background:var(--c-defer)}.kindtag{display:inline-block;font-size:11px;font-weight:750;border:1px solid #d6dbe5;border-radius:3px;padding:1px 5px;margin-right:6px;color:#4f5969}.kindtag.mitigate{border-color:#f0cf86;background:#fff7e4;color:#765017}
.workspaceinner>*{min-width:0}
  @media(max-width:1100px){.hero{grid-template-columns:1fr}.benchmark{grid-template-columns:1fr}.workspaceinner{grid-template-columns:300px minmax(0,1fr)}.resultbody{grid-template-columns:1fr}.compare{border-right:0;border-bottom:1px solid #e4e7ed}}
  @media(max-width:820px){.outcomes{grid-template-columns:1fr 1fr}.outcome{border-left:1px solid var(--line);border-top:0}.kpis{grid-template-columns:1fr 1fr}.kpi+.kpi{border-left:1px solid var(--line)}.workspaceinner{grid-template-columns:minmax(0,1fr)}.queuetable{display:block;overflow-x:auto}.empty{grid-template-columns:1fr}.resulthead{grid-template-columns:104px 1fr}.priority{height:54px}.reportlinks{grid-column:2;justify-items:start}.flow{grid-template-columns:1fr}.arrow{transform:rotate(90deg)}.decision{grid-column:1}.ssvcflow{grid-template-columns:1fr 1fr}.ssvcinputtable{display:block;overflow-x:auto}}
  @media(max-width:520px){h1{font-size:43px}.topbar{padding:0 16px}.brand{font-size:13px}.hero{padding-left:16px;padding-right:16px}.kpis{padding-left:16px;padding-right:16px}.prioritylegend{grid-template-columns:1fr 1fr}.prioritylegend>div{border-bottom:1px solid #e2e6ee}.sectiontitle{align-items:flex-start;gap:10px}.decisionactions{align-items:flex-end;flex-direction:column}.enginecontrol{min-width:0}.enginecontrol select{min-width:175px}.resulthead{padding:15px}.resultbody>div,.metricrow{padding-left:15px;padding-right:15px}.versus{grid-template-columns:1fr}.vs{text-align:center}}

  [hidden]{display:none!important}
  body{font-size:14px;line-height:1.45;height:100dvh;display:flex;flex-direction:column;overflow:hidden}
  .topbar{height:56px;flex:none;padding:0 24px;position:static}.brand{font-size:15px;gap:8px}.brand small{font-weight:400;letter-spacing:0;color:#a5afc1;margin-left:18px;font-size:12px}.topactions{display:flex;gap:8px}
  .btn{padding:9px 13px;box-shadow:none!important}.btn.small{font-size:12px;padding:7px 10px}.btn:focus-visible,button:focus-visible,summary:focus-visible,a:focus-visible{outline:2px solid #4053ba;outline-offset:3px}
  .kpis{width:100%;max-width:none;padding:0 24px;flex:none;display:flex;height:48px;margin:0;background:#10151f;gap:28px;align-items:center}.kpi,.kpi+.kpi{display:flex;gap:8px;align-items:baseline;border:0;padding:0;background:none}.kpi .value{font-size:18px}.kpi .label{font-size:10px;letter-spacing:.04em}
  .workspace{flex:1;min-height:0;padding:18px 20px;border-radius:0;overflow:hidden;background:#f0f2f7}.workspaceinner{height:100%;max-width:none;grid-template-columns:256px minmax(0,1fr);gap:20px}
  .sidebar,.decisionpane{display:flex;flex-direction:column;min-height:0;min-width:0}.sidebar{border-right:1px solid #d9deea;padding-right:18px}.sectiontitle{flex:none;align-items:center;margin:0 0 12px;gap:8px}.sectiontitle h2{font-size:20px}.sectiontitle span{font:12px/1.4 inherit;text-transform:none;letter-spacing:0;display:block;margin-top:3px}.sidebarhint{font-size:12px;color:#70798a;margin:0 0 14px}.targetlist{display:flex;flex-direction:column;gap:8px;overflow-y:auto;min-height:0;flex:1;padding:2px}.target{padding:0;box-shadow:none;flex:none}.target:hover{transform:none}.target.selected{border-color:#5368e8;box-shadow:0 0 0 1px #5368e8}.targetselect{width:100%;text-align:left;border:0;background:transparent;padding:12px;color:#242d40;border-radius:8px}.targetselect[aria-pressed=true]{background:#f0f2ff}.targetname{font-size:14px;font-weight:750;display:block}.targetmeta{font-size:11.5px;color:#697386;display:block;margin-top:5px;overflow-wrap:anywhere}.targetstate{display:flex;align-items:center;gap:6px;font-size:12px;margin-top:9px;color:#4659bf}.targetstate:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}.targetstate.failed{color:#b8322a}.sidebarfoot{padding-top:12px;display:grid;gap:8px}.sidebarfoot .btn{width:100%}.sidebarfoot .hint{font-size:11px;text-align:center}.privacy{font-size:11px;margin-bottom:10px}
  .enginecontrol{min-width:0}.enginevalue{background:transparent;border:0;padding:0;font-size:12px}.enginelabel{font-size:9px}.enginecontrol select{font-size:12px;min-width:0}.decisionactions{gap:14px}
  .outcomesummary{flex:none;display:grid;grid-template-columns:70px minmax(0,1fr);padding:9px 14px;gap:14px;margin-bottom:12px;box-shadow:none}.outcomesummary .donut{width:64px;height:64px}.outcomesummary .microtitle{margin:0 0 5px;font-size:10px;letter-spacing:.04em}.outcomerows{grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.outcomerow{padding:0;border:0;display:flex;align-items:center;justify-content:space-between;gap:6px}.outcomerow .name{font-size:12px}.outcomerow .name i{width:7px;height:7px}.outcomerow .count{font-size:20px;margin:0}.outcomerow .count small{font-size:10px}.outcomerow .meaning{display:none}
  #fleetbar{padding:7px 12px;margin-bottom:8px;font-size:12px;flex:none;max-height:125px;overflow:auto}#fleetbar summary{cursor:pointer;font-weight:650}
  .results{flex:1;min-height:0;gap:10px}.result{min-height:0;display:flex;flex-direction:column;flex:1;box-shadow:0 4px 16px #1e284108}.resulthead{grid-template-columns:125px minmax(0,1fr) auto;padding:13px 16px;gap:14px;flex:none}.priority{height:auto;min-height:32px;font-size:12px;padding:7px}.prioritymeaning{font-size:9px;margin-top:3px}.prioritydue{font-size:10px;margin-top:2px}.rname{font-size:12px;margin-bottom:4px;overflow-wrap:anywhere}.action{font-size:17px;line-height:1.3;overflow-wrap:anywhere}.reportlinks{gap:5px}.reportlink{font-size:12px}.resulttools{display:flex;gap:8px;margin-top:6px;align-items:center}.textbutton{border:0;background:transparent;padding:0;color:#4053ba;font-size:12px;font-weight:650;text-decoration:underline;text-underline-offset:3px}
  .resultnotice{flex:none;padding:6px 16px;background:#fff8e8;color:#785921;border-bottom:1px solid #ecd8ad;font-size:12px;overflow-wrap:anywhere}.resultnotice summary{cursor:pointer}.resultnotice p{margin:6px 0}.resulttabs{display:flex;gap:18px;padding:0 16px;border-bottom:1px solid #dfe4ee;flex:none}.resulttab{background:none;border:0;border-bottom:2px solid transparent;color:#6c7688;font-weight:650;font-size:12px;padding:10px 0;white-space:nowrap}.resulttab[aria-selected=true]{color:#3048c5;border-color:#5368e8}.tabcount{font-size:10px;background:#edf0f7;border-radius:9px;padding:1px 5px;margin-left:4px}.tabcount.warn{background:#fff0cf;color:#8b5918}.resultpanel{min-height:0;overflow:auto;flex:1;padding:14px 16px}.resultpanel:focus{outline-offset:-3px}.resultpanel .treeview{padding:0;border:0}.treeview>summary{font-size:14px}.treepick{margin:8px 0 10px;flex-wrap:nowrap}.treepick label{display:flex;align-items:center;gap:10px;min-width:0;flex:1;text-transform:none;letter-spacing:0;color:#697386;font-size:12px}.treepick select{min-width:0;max-width:650px;font-size:13px;padding:7px 10px}.treecanvas{overflow:hidden;border-color:#e3e7ef}.treecanvas svg{min-width:0;max-height:260px;width:100%;height:auto}.treelegend{font-size:11px;margin-top:7px}.pathsources{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:10px}.pathsource{border-left:2px solid #d9dfed;padding-left:9px;font-size:11px;color:#6c7688;overflow-wrap:anywhere}.pathsource strong{font-size:12px;color:#303a4c;display:block;margin-bottom:2px}.pathsource.assumed{border-color:#eaa51a;background:#fff9eb}.pathsource span{display:block}.evidencelinks{gap:5px;margin-top:10px}.evidencelinks a,.evidencelinks span{font-size:11px;padding:3px 7px}.pathcontext{display:flex;gap:12px;justify-content:space-between;font-size:12px;color:#5c677b;margin-top:8px;flex-wrap:wrap}.pathcontext b{color:#2d3441}.pathcontext .policyhint{color:#7b643c}
  .actionqueue,.ssvcinputreview{padding:0;border:0}.actionqueue summary,.ssvcinputreview summary{font-size:14px}.queuetable{font-size:12px}.queuetable th{font-size:10px}.queuetable th,.queuetable td{padding:8px 6px}.queuewrap{overflow-x:auto}.queuetable .cves{font-size:11px}.resultbody{grid-template-columns:minmax(0,1fr)}.compare,.explain{padding:0;border:0}.resultpanel .metricrow{padding:8px 0;gap:5px;background:none}.metric{font-size:11px}.resultpanel .confirmbar{margin:8px 0}.resultpanel .signal{padding:8px}.resultpanel .signalgrid{margin-bottom:10px}.resultpanel .factor{padding:9px}.resultpanel .microtitle{margin-top:12px}.resultpanel .compare{margin-top:18px}.ssvcinputtable select{min-width:130px}.empty{flex:1;min-height:0;display:flex;align-items:center;justify-content:center;padding:24px}.emptycontent{max-width:610px;width:100%}.emptycontent .eyebrow{color:#5264d9;font-size:11px}.emptycontent h3{font-size:30px;line-height:1.15;letter-spacing:-.03em;margin:12px 0}.emptycontent p{color:#6b7486;font-size:14px;max-width:58ch;margin:0 0 22px}.startsteps{display:flex;gap:12px;margin-bottom:24px}.startstep{flex:1;background:#f6f8fc;padding:13px;border:1px solid #e3e7ef;border-radius:7px;font-size:12px;color:#657083}.startstep b{display:block;color:#323e57;margin-bottom:5px}.startstep span{color:#5368e8;font-family:Consolas,monospace;margin-right:5px}.startactions{display:flex;gap:10px;flex-wrap:wrap}.emptycontent .targetactions{margin-top:18px}.targetsummary{display:flex;gap:7px;flex-wrap:wrap;margin:14px 0}.targetsummary .tag{font-size:10px}.statecard{display:flex;align-items:flex-start;justify-content:center;flex-direction:column;padding:32px}.statecard strong{font-size:22px}.statecard span{font-size:14px;max-width:650px}.statecard .scanline{width:100%;max-width:500px}.statecard .btn{margin-top:12px}.previousresult{font-size:12px;color:#667183}
  dialog{max-height:calc(100dvh - 32px);overflow:auto}#contextdialog{width:min(1020px,calc(100% - 32px));background:#fff}#contextdialog .add{margin:0;border:0;box-shadow:none}.dialogclose{float:right;margin:12px 14px;position:relative;z-index:1}.addhead{min-height:56px;padding:15px 18px}.addhead .hint{font-size:12px}.form{padding:14px 18px}.ssvcblock{grid-template-columns:repeat(3,minmax(0,1fr));padding:10px}.ssvcblock .derived{grid-column:1/-1;display:flex;align-items:center;gap:15px;padding:9px 12px}.derivednote{max-width:350px;font-size:11px}.derivedlabel .standardtag{display:none}.derivedvalue{flex:1}.derivedvalue span{font-size:11px}.ssvcfield .standardtag{display:none}.fieldq{font-size:12px;min-height:35px}.fieldnow{font-size:12px}.fieldnow.fallback{font-size:11.5px}.form>.hint{font-size:12px}.ssvcabout{font-size:12px}.advcols{grid-template-columns:1fr 1fr}.fieldhelp{font-size:12px}.toast{z-index:100;max-width:min(440px,calc(100vw - 32px));font-size:13px;pointer-events:none}
  @media(min-width:1001px) and (max-height:760px){.workspace{padding-top:12px;padding-bottom:12px}.sectiontitle{margin-bottom:8px}.outcomesummary{margin-bottom:8px;padding:7px 12px;grid-template-columns:56px minmax(0,1fr)}.outcomesummary .donut{width:52px;height:52px}.resulthead{padding:10px 14px}.resultpanel{padding:10px 14px}.treecanvas svg{max-height:210px}.pathsources{margin-top:7px}.treepick{margin:5px 0 7px}.treelegend{margin-top:5px}.evidencelinks{margin-top:7px}}
  @media(max-width:1100px){.workspaceinner{grid-template-columns:220px minmax(0,1fr);gap:14px}.sidebar{padding-right:12px}.outcomerows{grid-template-columns:repeat(4,minmax(0,1fr));gap:6px}.outcomerow .name{font-size:11px}.outcomerow .count small{display:none}.resulthead{grid-template-columns:110px minmax(0,1fr)}.reportlinks{grid-column:1/-1;display:flex;gap:16px}.pathsources{gap:6px}.brand small{display:none}}
  @media(max-width:1000px){body{height:auto;min-height:100dvh;display:block;overflow:auto}.workspace{overflow:visible;min-height:calc(100dvh - 104px)}.workspaceinner{height:auto}.sidebar{max-height:650px}.decisionpane{min-height:650px}.results{min-height:500px}.resultpanel{max-height:720px;overflow:auto}.kpis{gap:16px}.kpi .label{font-size:9px}.kpi .value{font-size:15px}.treecanvas{overflow-x:auto}.treecanvas svg{min-width:740px}.pathsources{grid-template-columns:repeat(2,minmax(0,1fr))}.treepick{flex-wrap:wrap}.ssvcblock{grid-template-columns:repeat(3,minmax(0,1fr))}}
  @media(max-width:700px){.topbar{padding:0 12px}.brand{font-size:12px}.brandmark{display:none}.topactions{gap:4px}.topactions .btn{font-size:10px;padding:6px}.kpis{height:auto;min-height:48px;flex-wrap:wrap;gap:6px 16px;padding:8px 12px}.kpi .label{font-size:9px}.workspace{padding:14px 12px}.workspaceinner{display:flex;flex-direction:column;gap:18px}.sidebar{border:0;padding:0;max-height:250px}.sidebarhint,.sidebarfoot .hint{display:none}.targetlist{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));max-height:160px;flex:none}.sidebarfoot{padding-top:8px}.decisionpane{min-height:600px}.sectiontitle h2{font-size:18px}.sectiontitle span{font-size:10px}.decisionactions{flex-direction:row;align-items:center;gap:8px}.enginecontrol{display:none}.outcomesummary{grid-template-columns:48px minmax(0,1fr);gap:10px}.outcomesummary .donut{width:44px;height:44px}.outcomerows{grid-template-columns:repeat(2,minmax(0,1fr))}.outcomerow .count{font-size:15px}.outcomerow .name{font-size:10px}.resulttabs{gap:14px;overflow-x:auto}.resulttab{font-size:11px}.resulthead{padding:12px;grid-template-columns:100px minmax(0,1fr);gap:10px}.action{font-size:15px}.resultpanel{padding:12px}.startsteps{flex-direction:column;gap:6px}.startstep{padding:10px}.emptycontent h3{font-size:26px}.empty{padding:20px}.addrow,.ssvcblock,.advcols{grid-template-columns:1fr}.ssvcblock .derived{display:grid}.derivednote{max-width:none}.form{padding:12px}.addhead{display:block;padding:14px}.addhead .hint{display:block;max-width:75%}.ssvcfield .fieldq{min-height:0}.advcol+.advcol{border-left:0;padding-left:0}.formactions{justify-content:flex-start}.formactions .btn{flex:none}}
  @media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;animation:none!important;transition:none!important}}

  @media(min-width:1001px){.kpis{height:36px}.workspace{padding-top:12px;padding-bottom:12px}.sectiontitle{margin-bottom:8px}.sectiontitle span{font-family:inherit;font-size:12px}.outcomesummary{padding:7px 14px;grid-template-columns:50px minmax(0,1fr);margin-bottom:10px;min-height:64px}.outcomesummary .donut{width:48px;height:48px}.resulthead{padding:10px 16px}.resultpanel{padding:10px 16px}.treepick{margin:4px 0 8px}.treecanvas svg{max-height:210px}.pathsources{margin-top:7px}.pathcontext{margin-top:6px}.evidencelinks{margin-top:7px}.treelegend{margin-top:5px}}

  /* Keep the introduction as the entry page; the workspace has its own viewport. */
  body{font-size:16px}
  a.btn,.brand{text-decoration:none}
  .landing{flex:1;min-height:0;overflow:auto;display:flex;flex-direction:column;justify-content:center;gap:28px;padding:28px clamp(24px,4vw,64px)}
  .landing .hero{width:100%;max-width:1500px;padding:0;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);gap:40px}
  .landing h1{font-size:clamp(52px,5.5vw,80px);line-height:1.03;margin:16px 0 20px}
  .landing .hero p{font-size:18px;line-height:1.6;margin-bottom:24px}
  .landing .eyebrow{font-size:12px;letter-spacing:.1em}
  .landing .btn{font-size:16px;padding:11px 16px}
  .landing .proof{padding:20px}.landing .proofhead{font-size:12px;letter-spacing:.03em;margin-bottom:16px}
  .landing .node{padding:12px 10px;min-height:126px}.landing .node small{font-size:14px}.landing .nodecode{font-size:11px}
  .landing .decision{padding:12px;gap:12px}.landing .decision b{font-size:16px}.landing .decision span{font-size:13px}.landing .decision .outcome-now{font-size:20px}
  .landing .benchmark{width:100%;max-width:1500px;padding:0;margin:0 auto;grid-template-columns:minmax(0,.85fr) minmax(0,2fr)}
  .landing .benchmarkcopy{padding:20px}.landing .benchmarkcopy h2{font-size:28px;margin:12px 0}.landing .benchmarkcopy p{font-size:14px}
  .landing .outcome{padding:16px 12px}.landing .outcome strong{font-size:17px}.landing .factorquestion{font-size:14px}.landing .outcome small{font-size:13px}

  /* Use the sidebar's spare height for totals instead of shrinking every label. */
  .workspaceinner{grid-template-columns:248px minmax(0,1fr);gap:18px}
  .sidebar{padding-right:16px}.sidebarhint{font-size:14px}
  .sidebar .kpis{display:grid;grid-template-columns:1fr 1fr;gap:12px 8px;height:auto;min-height:0;padding:16px 0 4px;background:none;border-top:1px solid #d9deea;margin-top:16px}
  .sidebar .kpi{display:flex;flex-direction:column;gap:2px;align-items:flex-start}
  .sidebar .kpi:last-child{grid-column:1/-1}.sidebar .kpi .value{font-size:20px;color:#28344c}
  .sidebar .kpi .label{font-size:12px;color:#5b667b;text-transform:none;letter-spacing:0}
  .btn.small,.brand small,.sidebarfoot .hint{font-size:14px}.brand{font-size:16px}
  .targetname{font-size:16px}.targetmeta,.targetstate{font-size:14px}.targetselect{padding:12px}
  .sectiontitle h2{font-size:22px}.sectiontitle span{font-family:inherit;font-size:14px;color:#5b667b}
  .enginevalue,.enginecontrol select{font-size:14px}.enginelabel{font-size:11px}
  .outcomesummary .microtitle{font-family:inherit;font-size:12px;letter-spacing:0;color:#5b667b}
  .outcomerow .name{font-size:14px}.outcomerow .count small{font-size:12px}
  .resulthead{grid-template-columns:110px minmax(0,1fr) auto;gap:12px}
  .priority{font-size:14px}.prioritymeaning{font-size:11px}.prioritydue{font-family:inherit;font-size:12px}
  .rname{font-size:14px;color:#5b667b}.action{font-size:18px}.reportlink,.textbutton{font-size:14px}
  .resulttab{font-size:15px;padding:10px 0}.tabcount{font-size:12px}
  .treepick label{font-size:14px}.treepick select{font-size:15px;max-width:none}
  .tree .node text,.tree .leaf text{font-size:16px}.tree .root text{font-size:14px}.tree .colhead{font-size:13px;letter-spacing:0}
  .treelegend{font-size:13px;color:#596579}.pathsource{font-size:13px;color:#596579}.pathsource strong{font-size:14px}
  .pathcontext{font-size:13px;gap:5px 12px}.evidencelinks a,.evidencelinks span{font-size:13px}
  .queuetable,.ssvcinputtable{font-size:14px}.queuetable th,.ssvcinputtable th{font-size:12px}.queuetable .cves,.inputsource{font-size:13px}
  .ssvcinputtable select,.metric,.fieldq,.fieldnow,.fieldnow.fallback,.fieldhelp,.derivedvalue span,.derivednote,.ssvcabout,.form>.hint,.addhead .hint{font-size:14px}
  .emptycontent p,.statecard span{font-size:16px}.startstep{font-size:14px}.emptycontent .eyebrow{font-size:13px}
  .resultnotice,.toast,.privacy{font-size:14px}
  @media(min-width:1001px) and (max-height:700px){.workspace{padding-top:8px;padding-bottom:8px}.sectiontitle{margin-bottom:6px}.outcomesummary{min-height:46px;grid-template-columns:34px minmax(0,1fr);padding:5px 12px;margin-bottom:8px}.outcomesummary .donut{width:32px;height:32px}.outcomesummary .microtitle{display:none}.resulthead{padding-top:6px;padding-bottom:6px}.resultpanel{padding-top:8px;padding-bottom:8px}.resulttab{padding:8px 0}}
  @media(min-width:1001px) and (max-height:760px){.landing{gap:24px;padding-top:24px;padding-bottom:24px}.landing h1{font-size:60px}.landing .benchmarkcopy h2{font-size:25px}.landing .outcome{padding-top:12px;padding-bottom:12px}}
  @media(max-width:1100px){.brand small{display:none}.workspaceinner{grid-template-columns:220px minmax(0,1fr)}.landing{justify-content:flex-start}.landing .hero,.landing .benchmark{grid-template-columns:1fr}.landing .proof{margin-top:8px}.landing .benchmarkcopy{border-bottom:0}}
  @media(max-width:1000px){.sidebar .kpis{flex:none}.treecanvas svg{min-width:920px}.landing{overflow:visible}.landing .hero{gap:24px}.landing .outcomes{grid-template-columns:repeat(2,1fr)}}
  @media(max-width:700px){.brand{font-size:14px}.topbar{height:auto;min-height:64px;gap:8px}.topactions .btn{font-size:13px;padding:7px 9px}.topactions{flex-wrap:wrap;justify-content:flex-end;padding:8px 0}.workspaceinner{display:flex}.sidebar{max-height:none}.sidebar .kpis{grid-template-columns:repeat(3,1fr);gap:10px;padding-top:12px}.sidebar .kpi:last-child{grid-column:auto}.sidebar .kpi .value{font-size:18px}.sidebarfoot .hint{display:none}.targetlist{max-height:180px}.sectiontitle span{font-size:14px}.outcomerow .name{font-size:14px}.resulthead{grid-template-columns:100px minmax(0,1fr)}.resulttabs{gap:18px}.landing{padding:28px 20px;gap:24px}.landing h1{font-size:52px}.landing .hero p{font-size:17px}.landing .proofhead{flex-wrap:wrap;gap:5px}.landing .node{min-height:0}.landing .decision{flex-wrap:wrap}.landing .outcome{border-left:1px solid var(--line)}.landing .heroactions{flex-direction:column;align-items:stretch}.landing .heroactions .btn{text-align:center}}
</style>
<style id="console-theme">
  @font-face{font-family:"IBM Plex Sans";src:url("/fonts/IBMPlexSans-Regular.woff2") format("woff2");font-weight:400;font-style:normal;font-display:swap}

  @font-face{font-family:"IBM Plex Sans";src:url("/fonts/IBMPlexSans-Medium.woff2") format("woff2");font-weight:500;font-style:normal;font-display:swap}

  @font-face{font-family:"IBM Plex Sans";src:url("/fonts/IBMPlexSans-SemiBold.woff2") format("woff2");font-weight:600;font-style:normal;font-display:swap}

  @font-face{font-family:"IBM Plex Mono";src:url("/fonts/IBMPlexMono-Regular.woff2") format("woff2");font-weight:400;font-style:normal;font-display:swap}

  @font-face{font-family:"IBM Plex Mono";src:url("/fonts/IBMPlexMono-Medium.woff2") format("woff2");font-weight:500;font-style:normal;font-display:swap}

  :root{
  color-scheme:dark;
  --bg:#060a13;--s1:#0b1222;--s2:#101a2f;--line:#1b2740;--line2:#26344f;
  --ink:#e4eaf6;--mut:#8391ab;--dim:#56637c;--acc:#22d3ee;--acc2:#3b82f6;
  --glow:0 0 0 1px var(--acc);
  --c-immediate:#ff5a5f;--c-outofcycle:#ffb340;--c-scheduled:#5b8cff;--c-defer:#64748b;
  --void:var(--bg);--void2:var(--s1);--panel:var(--s1);--panel2:var(--s2);
  --muted:var(--mut);--paper:var(--bg);--dark:var(--ink);--glass:var(--s1);--surface:var(--s2);
  --hot:var(--ink);--amber:var(--mut);--blue:var(--acc2);--cyan:var(--acc);--accent:var(--acc);
  --immediate:var(--c-immediate);--outofcycle:var(--c-outofcycle);--scheduled:var(--c-scheduled);--defer:var(--c-defer);
  --ui-font:"IBM Plex Sans","Segoe UI",system-ui,sans-serif;
  --mono-font:"IBM Plex Mono",ui-monospace,Consolas,monospace;
  }

  /* Existing layout, typography sizing, and responsive behavior. */
  body{padding:0;gap:0;font-weight:400;letter-spacing:.005em}
  *{scrollbar-width:thin}
  .topbar{min-height:60px;padding:0 24px;border:0;border-bottom:1px solid var(--line)}
  .brand{font-weight:650;letter-spacing:.025em;gap:7px}
  .brand small{font-size:13px}
  .btn{font-weight:600;transition:background .18s,border-color .18s,transform .18s}
  .btn.primary{font-weight:600}
  .btn:disabled{opacity:.45;transform:none}
  .btn:focus-visible,button:focus-visible,summary:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline-offset:3px}
  .landing,.workspace{border:0}
  .landing{padding:28px 32px;gap:26px}
  .landing h1{font-weight:650;letter-spacing:-.045em}
  .eyebrow,.landing .eyebrow{font-weight:650;letter-spacing:.12em}
  .proof:after{display:none}
  .landing .benchmark{gap:14px}
  .landing .outcomes{gap:10px}
  .landing .outcome{border:1px solid var(--line)}
  .workspace{padding:18px}
  .workspaceinner{gap:20px}
  .sidebar{padding-right:18px}
  .sectiontitle h2{font-weight:600;letter-spacing:-.025em}
  .target{overflow:hidden}
  .targetname{font-weight:600}
  .sidebar .kpi .value{font-weight:600}
  .outcomesummary .microtitle,.microtitle{letter-spacing:.055em}
  .outcomerow .count{font-weight:600}
  .action{font-weight:600}
  .resulttabs{gap:22px}
  .resulttab{font-weight:500}
  .tree .node text{font-weight:400}
  .tree .node.on text{font-weight:600}
  .tree .colhead{font-weight:500}
  .emptycontent h3{font-weight:600}
  dialog,#contextdialog{border:1px solid var(--line)}
  dialog::backdrop{backdrop-filter:blur(7px)}

  @media(max-width:1100px){.workspace{padding:14px}
  .landing{padding:24px}
  }

  @media(max-width:700px){.topbar{padding:8px 12px}
  .brand{font-size:13px}
  .topactions .btn{font-size:12px}
  .workspace{padding:14px 12px}
  .sidebar{padding-right:0}
  .landing{padding:24px 18px}
  .landing h1{font-size:46px}
  .landing .benchmark{gap:12px}
  .landing .outcomes{gap:8px}
  .outcomesummary{padding:10px}

  }
  .kpi .value,.outcomerow .count,.donutlabel,.donutcount,.metric,.queuetable td.num{font-variant-numeric:tabular-nums}
  .brand{font-weight:600;letter-spacing:.01em}
  .sectiontitle h2,.emptycontent h3,.dialogbody h3,.addhead h3{font-weight:500;letter-spacing:-.015em}
  .targetname,.action,.btn,.resulttab,.fieldlabel,.outcomerow .name{font-weight:600}
  .proofhead,.microtitle,.enginelabel,.kpi .label{letter-spacing:.03em}
  .brand small{font-size:12px}
  .landing h1{font-size:clamp(38px,4vw,64px);letter-spacing:-.05em}
  .targetname,.sectiontitle h2{font-size:18px}
  .targetmeta,.targetstate{font-size:12px}
  .action{font-size:16px}
  .resulttools{flex-wrap:wrap}
  .resulttab{font-size:13px}
  .tree .colhead{font-size:11px}
  .donutlabel{font:500 28px var(--ui-font)}
  .donutsub{font:400 10px var(--ui-font);letter-spacing:.04em}
  .outcomesummary{grid-template-columns:100px minmax(0,1fr);min-height:120px;padding:12px 20px;gap:26px}
  .outcomesummary .donut{width:100px;height:100px;overflow:visible}
  .outcomesummary .microtitle{display:block;margin-bottom:14px;font-size:11px}
  .outcomerows{gap:16px}
  .outcomerow{display:block;border:0;padding-left:0}
  .outcomerow .name{font-size:12px;white-space:nowrap}
  .outcomerow .count{display:flex;align-items:baseline;gap:8px;font-size:25px;margin-top:6px}
  .outcomerow .count small{display:inline;font-size:12px;margin:0}
  .outcomerow .count{font-weight:500}
  .outcomerow .name{font-weight:400}
  .pathsources{gap:0;margin-top:16px;padding:14px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
  .pathsource{border:0;padding:0 16px;line-height:1.5}
  .pathsource:first-child{padding-left:0}
  .pathsource+.pathsource{border-left:1px solid var(--line)}
  .pathsource .sourcekey{font-size:12px;font-weight:400;letter-spacing:0}
  .pathsource strong{font-size:16px;font-weight:500;margin:3px 0}
  .pathsource .sourcevia{font-size:12px;font-weight:400}

  @media(min-width:1001px){.decisionpane{overflow-y:auto;scrollbar-gutter:stable}
  .results,.result{flex:none}
  /* A hidden overflow ancestor prevents the tabs from sticking to the pane. */
  .result{overflow:visible}
  .resultpanel{flex:none;overflow:visible}
  .resulttabs{position:sticky;top:0;z-index:3}

  }
  .assumedmark{font-weight:700}

  @media(max-width:1100px){.outcomerows{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  .outcomerow .count{font-size:20px;margin-top:2px}
  }

  @media(max-width:700px){.outcomesummary{grid-template-columns:100px minmax(0,1fr);padding:12px;gap:12px}
  .outcomesummary .donut{width:100px;height:100px}
  .outcomesummary .microtitle{font-size:10px;margin-bottom:10px}
  .outcomerow{padding-left:7px}
  .outcomerow .name{font-size:10px;white-space:normal}
  .outcomerow .count{font-size:18px;gap:5px}
  .outcomerow .count small{font-size:10px}
  .brand{font-size:12px}
  .topactions .btn{font-size:11px}
  .pathsources{row-gap:16px}
  .pathsource{padding:0 10px}
  .pathsource:nth-child(odd){border-left:0;padding-left:0}

  }

  /* Token-based surfaces; outcome colors are reserved for assessment results. */
  body{background:var(--bg);color:var(--ink);font-family:var(--ui-font);font-variant-numeric:tabular-nums}

  body *{font-family:var(--ui-font)}
  .mono,.eyebrow,.proofhead,.nodecode,.decision .outcome-now,.factorcode,.kpi .value,.kpi .label,
  .sectiontitle span,.enginelabel,.standardtag,.ssvcprogress,.fieldnum,.derivedlabel,.targetid,.tag,
  .priority,.prioritydue,.metric,.microtitle,.barvalue,.outcomemicro b,.factor span,.decisionline b,
  .signal b,.evidenceicon,.advisoryline a,.advisoryline span,.outcomerow .count,.outcomerow .count small,
  .breakdown .chip b,.queuetable td.num,.startstep span,.vs,.tree .node text,.tree .root text,
  .tree .leaf text,.tree .colhead{font-family:var(--ui-font)}

  *{scrollbar-color:var(--line2) transparent}

  ::selection{background:var(--acc);color:var(--bg)}

  .topbar{background:var(--bg);border-color:var(--line);box-shadow:none}

  .brand,.brand span,.landing h1 em,.eyebrow,.landing .eyebrow,.emptycontent .eyebrow{color:var(--ink)}

  .brandmark{border-color:var(--acc);background:var(--acc);border-radius:5px}

  .brandmark:before,.brandmark:after{background:var(--bg)}

  .statusdot{background:var(--mut);box-shadow:none}

  .landing,.workspace{background:var(--bg);color:var(--ink);box-shadow:none}

  .proof,.benchmarkcopy,.outcome,.lightpanel,.result,.outcomesummary,dialog,#contextdialog{background:var(--s1);border-color:var(--line);border-radius:8px;box-shadow:none}

  .node,.landing .node,.target,.startstep,.emptyresult,.factor,.signal,.outcomemicro,.decisionnote,.ssvcfield,.derived,.contextintro,.ssvcblock,.treecanvas{background:var(--s2);border-color:var(--line);border-radius:6px;box-shadow:none;color:var(--ink)}

  .sidebar{background:var(--s1)}

  .target{background:var(--s1)}
  .target:hover{border-color:var(--line2)}

  .target.selected{border-color:var(--acc);box-shadow:var(--glow)}

  .targetselect{color:var(--ink);border-radius:6px}
  .targetselect[aria-pressed=true]{background:var(--s2)}

  .btn,.btn.ghost,.btn.attach,.btn.danger,.sidebarfoot .btn{background:transparent;border-color:var(--line2);color:var(--ink);border-radius:6px;box-shadow:none}

  .btn:hover,.btn.ghost:hover,.btn.attach:hover,.btn.danger:hover,.sidebarfoot .btn:hover{background:var(--s2);border-color:var(--line2)}

  /* Solid accent: dark text meets 4.5:1 here; white does not. */
  .btn.primary{background:var(--acc);border-color:var(--acc);color:var(--bg)}
  .btn.primary:hover{background:color-mix(in srgb,var(--acc) 82%,var(--ink));border-color:color-mix(in srgb,var(--acc) 82%,var(--ink))}
  .btn{transition:background-color 160ms ease,border-color 160ms ease,transform 160ms cubic-bezier(.23,1,.32,1)}
  .btn:active:not(:disabled){transform:scale(.97)}
  @media (prefers-reduced-motion:reduce){.btn:active:not(:disabled){transform:none}}

  .btn:focus-visible,button:focus-visible,summary:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--acc);outline-offset:3px}

  .sidebar,.sidebar .kpis,.form,.advanced,.advcol+.advcol,.queuetable th,.queuetable td,.ssvcinputtable th,.ssvcinputtable td,.metricrow,.breakdown,.bodpanel,.resulthead,.resulttabs,.evidence li,.pathsources,.pathsource+.pathsource,.treeview,.actionqueue,.compare{border-color:var(--line)}

  .kpis,.metricrow,.ssvcinputreview,.resulthead{background:transparent}

  .sidebar .kpi .value,.kpi .value,.factorquestion,.outcome small b,.fieldname,.fieldnow b,.derivedvalue b,.signal b,.decisionnote b,.startstep b,.outcomerow .name,.outcomerow .count,.pathsource strong,.pathcontext b,.fieldlabel,.fieldhelp b,.advgroup,.advanced summary,.enginevalue{color:var(--ink)}

  .brand small,.landing .hero p,.landing .benchmarkcopy p,.proofhead,.node small,.decision span,.outcome small,.sidebarhint,.sidebarfoot .hint,.hint,.sectiontitle span,.enginelabel,.targetmeta,.targetid,.targetstate,.targetstate.failed,.sidebar .kpi .label,.microtitle,.outcomerow .count small,.outcomerow .meaning,.prioritymeaning,.prioritydue,.rname,.treelegend,.pathsource,.pathcontext,.pathsentence,.pathsentence .src,.pathsource .sourcekey,.pathsource .sourcevia,.queuetable th,.ssvcinputtable th,.queuetable .cves,.inputsource,.bodcell.reference b,.emptycontent p,.statecard span,.previousresult,.startstep,.emptyresult span,.factor span,.factor small,.signal span,.comparefoot,.outcomemicro span,.ssvcinputreview p,.actionqueue p,.evidence small,.dialogbody p,.addhead .hint,.fieldhelp,.fieldq,.fieldnow,.derivednote,.derivedvalue span,.ssvcabout,.contextintro span,.source,.emptycopy p{color:var(--mut)}

  .nodecode,.factorcode,.derivedlabel,.startstep span,.outcomemicro b,.decisionline b,.reviewflag,.assumedmark,.pathcontext .policyhint,.pathsource.assumed strong{color:var(--ink)}

  .reportlink,.textbutton,.contextintro a,.ssvcabout a,.ssvcabout>summary,.evidencelinks a,.advisoryline a{color:var(--acc)}
  .source.ready{color:var(--ink)}

  .evidencelinks a:hover,.reportlink:hover,.textbutton:hover{color:var(--ink)}

  .tag,.tag.hot,.tag.demo,.tag.warn,.metric,.metric.alert,.metric.audit,.tabcount,.tabcount.warn,.kindtag,.kindtag.mitigate,.standardtag,.ssvcprogress,.ssvcprogress.done,.factorcode,.evidencelinks a,.evidencelinks span,.advisoryline a,.advisoryline span,.breakdown .chip{background:var(--s2);border-color:var(--line2);color:var(--mut);border-radius:4px}

  .evidencelinks a,.advisoryline a{color:var(--acc)}

  .privacy,.confirmbar,.resultnotice,.fieldnow.fallback,.patchtriagenote,.basis,.decisionnote{background:var(--s2);border-color:var(--line2);color:var(--mut);border-radius:6px}

  .patchtriagenote{color:var(--mut)!important}
  .patchtriagenote b,.fieldnow.fallback b{color:var(--ink)}

  .ssvcfield.set,.ssvcfield.pending{border-left-color:var(--line2)}

  .fieldnum,.ssvcfield.set .fieldnum,.evidenceicon,.evidenceicon.confirmed,.evidenceicon.attention{background:var(--s2);color:var(--ink)}

  .decision,.decisionline,.emptyviz{background:var(--s2);border-color:var(--line2);border-radius:6px;color:var(--ink)}

  .decision .outcome-now{color:var(--c-immediate)}
  .arrow{color:var(--mut)}
  .outcomesummary .microtitle,.treepick .fieldlabel{color:var(--mut)}

  .track,.scanline{background:var(--line)}
  .fill,.fill.epss,.fill.pt,.scanline:after{background:var(--mut)}

  .resulttabs{background:var(--s1)}
  .resulttab{color:var(--mut)}
  .resulttab:hover{color:var(--ink)}

  .outcomepill.immediate i{background:var(--c-immediate)}
  .outcomepill.out-of-cycle i{background:var(--c-outofcycle)}
  .outcomepill.scheduled i{background:var(--c-scheduled)}

  .donutlabel{fill:var(--ink)}
  .donutsub{fill:var(--mut)}
  .donut circle:not(.seg){stroke:var(--line2)}

  .pathsource.assumed{background:transparent}
  .queuetable tbody tr:hover,.ssvcinputtable tbody tr:hover{background:var(--s2)}

  input[type=text],select,select option{background:var(--s2);color:var(--ink);border-color:var(--line2);border-radius:6px;accent-color:var(--acc)}

  input::placeholder{color:var(--mut);opacity:1}

  dialog::backdrop{background:#060a13cc;backdrop-filter:blur(7px)}

  .toast,.toast.error{background:var(--s2);color:var(--ink);border-color:var(--line2);border-radius:6px;box-shadow:none}

  .statecard.failed,.statecard.running{border-left-color:var(--line2)}

  .cve,.hash{font-family:var(--mono-font)}
  .cve{font-weight:500}.hash{font-weight:400}

  /* Results retain their own palette; cyan denotes interaction and selection. */
  [data-outcome]{--outcome:var(--line2);--outcome-ink:var(--ink)}
  [data-outcome="immediate"]{--outcome:var(--c-immediate);--outcome-ink:var(--c-immediate)}
  [data-outcome="out_of_cycle"]{--outcome:var(--c-outofcycle);--outcome-ink:var(--c-outofcycle)}
  [data-outcome="scheduled"]{--outcome:var(--c-scheduled);--outcome-ink:var(--c-scheduled)}
  /* Keep Defer geometry at the exact token; lighten only text to meet AA. */
  [data-outcome="defer"]{--outcome:var(--c-defer);--outcome-ink:color-mix(in srgb,var(--c-defer) 70%,var(--ink))}
  .resulthead{border-top:2px solid var(--top,var(--line2));border-radius:8px 8px 0 0}
  .priority[data-outcome]{font:600 13px var(--ui-font);border:1px solid var(--outcome);color:var(--outcome-ink);background:color-mix(in srgb,var(--outcome) 8%,transparent);border-radius:5px}
  .priority.no-findings{color:var(--ink);background:var(--s2)}
  .resulttab[aria-selected=true]{color:var(--ink);border-color:var(--acc)}
  .tag.hot{border-color:color-mix(in srgb,var(--c-immediate) 40%,transparent);color:#ff8a8d;background:color-mix(in srgb,var(--c-immediate) 8%,transparent)}
  /* Decision path: a flat canvas where only the chosen route carries color. */
  .treecanvas{background:var(--s1);border:1px solid var(--line);border-radius:8px;padding:14px 16px 12px}
  .treecanvas svg,.treecanvas svg.tree{max-height:none}
  .tree .grid{pointer-events:none}
  .tree pattern circle{fill:var(--line)}
  .tree .colhead{fill:var(--mut);font:500 12px var(--ui-font);letter-spacing:0;text-transform:none}
  .tree .edge{fill:none;stroke:var(--line2);stroke-width:1}
  .tree .edge.on{stroke:var(--acc);stroke-width:2;stroke-linecap:round}
  .tree .edge.final{stroke:var(--outcome)}
  .tree .node rect{fill:var(--s1);stroke:var(--line2);stroke-width:1}
  .tree .node text{fill:var(--mut);font:400 13px var(--ui-font)}
  .tree .node.on rect{fill:var(--s2);stroke:var(--acc);stroke-width:1.5}
  .tree .node.on text{fill:var(--ink);font-weight:600}
  .tree .node.assumed rect,.tree .node.on.assumed rect{fill:var(--s2);stroke:var(--c-outofcycle);stroke-width:1.5;stroke-dasharray:4 3}
  .tree .assumedbadge circle{fill:var(--c-outofcycle);stroke:var(--s1);stroke-width:2}
  .tree .assumedbadge text{fill:var(--bg);font:700 11px var(--ui-font)}
  .tree .root rect{fill:var(--s2);stroke:var(--line2)}
  .tree .root text.cve{fill:var(--ink);font:500 13px var(--mono-font)}
  .tree .root text.asset{fill:var(--mut);font:400 12px var(--ui-font)}
  .tree .leaf rect{fill:var(--s1);stroke:var(--line2);stroke-width:1}
  .tree .leaf .dot{fill:var(--outcome)}
  .tree .leaf text{fill:var(--mut);font:400 13px var(--ui-font)}
  .tree .leaf.on rect{fill:color-mix(in srgb,var(--outcome) 14%,var(--s1));stroke:var(--outcome);stroke-width:1.5}
  .tree .leaf.on text{fill:var(--outcome-ink);font-weight:600}
  .tree .leaf.off{opacity:1}
  @media (prefers-reduced-motion:no-preference){
    .tree .edge.on{stroke-dasharray:1;stroke-dashoffset:1;animation:treedraw 220ms cubic-bezier(.23,1,.32,1) calc(var(--step) * 40ms) forwards}
  }
  @keyframes treedraw{to{stroke-dashoffset:0}}
  .treelegend{display:flex;flex-wrap:wrap;gap:6px 20px;list-style:none;margin:10px 0 0;padding:0;font-size:12px;color:var(--mut)}
  .treelegend li{display:flex;align-items:center;gap:8px}
  .treelegend .swatch{display:inline-grid;place-items:center;flex:none;box-sizing:border-box}
  .treelegend .swatch.path{width:18px;height:2px;border-radius:1px;background:var(--acc)}
  .treelegend .swatch.assumed{width:14px;height:14px;border-radius:50%;background:var(--c-outofcycle);color:var(--bg);font:700 10px/1 var(--ui-font);font-style:normal}
  .treelegend .swatch.alt{width:14px;height:10px;border:1px solid var(--line2);border-radius:3px}
  /* Sources wrap to two columns at this width; start each row flush left. */
  @media(max-width:1000px){.pathsources{row-gap:16px}.pathsource{padding:0 10px}.pathsource:nth-child(odd){border-left:0;padding-left:0}}
  /* Overview: flat flow chart; ribbons carry the outcome color, nodes stay neutral. */
  .overview{display:grid;gap:12px}
  .overviewhead h3{margin:0;font:600 15px var(--ui-font);color:var(--ink);letter-spacing:-.01em}
  .overviewhead span{display:block;margin-top:3px;font-size:12px;color:var(--mut)}
  .flowcanvas{overflow-x:auto}
  .treecanvas svg.flowchart{display:block;width:100%;min-width:720px;max-height:none;height:auto}
  .flowchart .colhead{fill:var(--mut);font:500 12px var(--ui-font)}
  .flowchart .ribbon{fill:var(--outcome);fill-opacity:.4;cursor:pointer;transition:fill-opacity 150ms ease}
  .flowchart .ribbon.dim{fill-opacity:.06}
  .flowchart .ribbon.hit{fill-opacity:.55;pointer-events:none}
  .flowchart .flownode[data-flow]{cursor:pointer}
  .flowchart .flownode rect{fill:var(--s1);stroke:var(--line2);stroke-width:1;transition:stroke 150ms ease}
  .flowchart .flownode text{fill:var(--ink);font:500 12px var(--ui-font);pointer-events:none}
  .flowchart .flownode .count{fill:var(--mut);font-variant-numeric:tabular-nums}
  .flowchart .flownode.empty text{fill:var(--mut)}
  .flowchart .flownode.empty rect{fill:transparent;stroke-dasharray:3 3}
  .flowchart .flownode.leaf .dot{fill:var(--outcome)}
  .flowchart .flownode.leaf:not(.empty) rect{stroke:color-mix(in srgb,var(--outcome) 60%,var(--line2))}
  .flowchart .flownode.on rect{fill:var(--s2);stroke:var(--acc);stroke-width:1.5}
  @media (hover:hover) and (pointer:fine){
    .flowchart .ribbon:hover{fill-opacity:.62}
    .flowchart .ribbon.dim:hover{fill-opacity:.2}
    .flowchart .flownode[data-flow]:hover rect{stroke:var(--acc)}
  }
  .flowchart .ribbon:focus-visible{fill-opacity:.62;outline:none;stroke:var(--acc);stroke-width:1.5}
  .flowchart .flownode:focus-visible{outline:none}
  .flowchart .flownode:focus-visible rect{stroke:var(--acc);stroke-width:2}
  .overviewbar{display:flex;align-items:center;justify-content:space-between;gap:10px;min-height:30px;font-size:12px;color:var(--mut)}
  .overviewtable td{vertical-align:middle}
  .overviewtable .openpath{font:500 12.5px var(--mono-font);color:var(--acc);padding:0;white-space:nowrap}
  .overviewtable .cve{font:500 12.5px var(--mono-font)}
  .assumedmark{display:inline-grid;place-items:center;width:15px;height:15px;border-radius:50%;background:var(--c-outofcycle);color:var(--bg);font:700 10px/1 var(--ui-font);vertical-align:1px;margin-left:2px}
</style></head>
<body>
<header class="topbar">
  <a class="brand" href="#home" aria-label="PatchTriage home"><span class="brandmark" aria-hidden="true"></span>PATCH<span>TRIAGE</span><small>Patch decision workspace</small></a>
  <div class="topactions"><a class="btn small ghost" id="home-link" href="#home" hidden>Home</a><a class="btn small ghost" id="workspace-link" href="#workspace">Open workspace →</a><button class="btn small run-control" id="demo">Run the offline demo</button></div>
</header>
<main class="landing" id="home" aria-labelledby="home-title">
<section class="hero">
  <div>
    <div class="eyebrow">Evidence-informed deployment decisions</div>
    <h1 id="home-title" tabindex="-1">Patch what matters <em>first.</em></h1>
    <p>Turn vulnerability evidence and your system context into a clear patching priority — with a decision path you can explain.</p>
    <div class="heroactions"><a class="btn primary" href="#workspace">Open workspace →</a><button class="btn ghost run-control" id="landing-demo">Try the offline demo</button></div>
  </div>
  <div class="proof" aria-label="PatchTriage decision flow">
    <div class="proofhead"><span>Why this patch first?</span><span>auditable signal path</span></div>
    <div class="flow">
      <div class="node"><span class="nodecode">01 / FIND</span><strong>Scanner evidence</strong><small>CVE · package · fixed version</small></div>
      <div class="arrow">→</div>
      <div class="node"><span class="nodecode">02 / THREAT</span><strong>Exploitation state</strong><small>Active · Public PoC · None · EPSS watch signal</small></div>
      <div class="arrow">→</div>
      <div class="node"><span class="nodecode">03 / STAKEHOLDER</span><strong>SSVC factors</strong><small>Exposure · Automatable · Human impact</small></div>
      <div class="decision"><div><b>Upgrade spring-beans on web-frontend</b><br><span>Active · Open · Automatable · High human impact → Immediate</span></div><div class="outcome-now">Immediate</div></div>
    </div>
  </div>
</section>

<section class="benchmark" aria-label="SSVC decision model">
  <div class="benchmarkcopy">
    <div class="eyebrow">CERT/CC SSVC · Deployer model</div>
    <h2>Severity informs. Your environment decides.</h2>
    <p>Four SSVC factors connect threat evidence to the impact on your system.</p>
  </div>
  <div class="outcomes">
    <div class="outcome"><span class="factorcode">SSVC · E</span><strong>Exploitation</strong><span class="factorquestion">What are attackers doing?</span><small><b>Active</b> (CISA KEV) · <b>Public PoC</b> · <b>None</b></small></div>
    <div class="outcome"><span class="factorcode">SSVC · EXP</span><strong>System exposure</strong><span class="factorquestion">How reachable is this system?</span><small><b>Open</b> · <b>Controlled</b> · <b>Small</b></small></div>
    <div class="outcome"><span class="factorcode">SSVC · A</span><strong>Automatable</strong><span class="factorquestion">Can exploitation be automated?</span><small><b>Yes</b> · <b>No</b> · reviewed per vulnerability</small></div>
    <div class="outcome"><span class="factorcode">SSVC · HI</span><strong>Human impact</strong><span class="factorquestion">What happens if exploitation succeeds?</span><small><b>Low</b> · <b>Medium</b> · <b>High</b> · <b>Very high</b>, from mission + safety</small></div>
  </div>
</section>

</main>



<section class="workspace" id="workspace" hidden>
  <div class="workspaceinner">
    <aside class="sidebar">
      <div class="sectiontitle"><h2>Targets</h2><button class="btn primary small" id="new-target">+ Add target</button></div>
      <p class="sidebarhint">Select a system to review its decisions.</p>
      <div class="privacy" id="privacy-note" hidden><b>Public service:</b> Do not upload confidential scanner output or private repository data. Anonymous evidence is retained temporarily.</div>

      <div class="targetlist" id="targetlist" aria-label="Registered targets"></div>
      <section class="kpis" aria-label="Workspace totals">
  <div class="kpi"><div class="value" id="k-targets">0</div><div class="label">Targets</div></div>
  <div class="kpi"><div class="value" id="k-kev">0</div><div class="label">known exploited</div></div>
  <div class="kpi"><div class="value" id="k-immediate">0</div><div class="label">Immediate decisions</div></div>
  <div class="kpi"><div class="value" id="k-audit">—</div><div class="label">Decisions verified</div></div>
  <div class="kpi" title="Share of Exploitation and Automatable values taken from a published or analyst-confirmed source instead of a conservative assumption."><div class="value" id="k-authoritative">—</div><div class="label">Inputs from authority</div></div>
</section>
      <div class="sidebarfoot"><button class="btn small" id="fleet-open">Import organization…</button><div class="hint">Scanner JSON · SBOM · Repository</div></div>
    </aside>

    <main class="decisionpane" aria-label="Patch decisions">
      <div class="sectiontitle"><div><h2 id="workspace-title" tabindex="-1">Patch decisions</h2><span id="workspace-step">1. Add a target → 2. Add evidence → 3. Run triage</span></div><div class="decisionactions">
        <div class="enginecontrol" aria-label="Decision engine"><small class="enginelabel">Decision engine</small><strong class="enginevalue" id="backend-static">SSVC deterministic</strong><select id="backend" aria-label="Decision engine" hidden></select></div>
        <button class="btn small run-control" id="runall">Run all</button>
      </div></div>
      <div class="outcomesummary lightpanel" id="outcomesummary" aria-label="SSVC outcome breakdown"></div>
      <details id="fleetbar" class="lightpanel" hidden></details>
      <div class="results" id="results" aria-live="polite"></div>
    </main>
  </div>
</section>
<dialog id="contextdialog" aria-labelledby="form-title"><button class="dialogclose btn small" id="context-close" aria-label="Close target form">Close ×</button>
      <section class="add lightpanel" id="targetform" aria-labelledby="form-title">
        <div class="addhead"><h3 id="form-title">Add a target</h3><span class="hint">Name your system. Add evidence after saving.</span></div>
        <div class="form">
          <div class="addrow">
            <label class="fieldlabel">System name<input type="text" id="f-name" maxlength="120" placeholder="e.g. checkout-api" aria-label="System name"></label>
            <label class="fieldlabel">Reference URL (optional)<input type="text" id="f-url" placeholder="Dashboard or repository link; not scanned" aria-label="Reference link URL"></label>
            <div class="formactions"><button class="btn primary" id="add">Add target</button><button class="btn" id="cancel-edit" type="button" hidden>Cancel</button></div>
          </div>
          <div class="ssvcblock">
            <div class="ssvchead">
              <div><strong>Patch priority context</strong><span class="standardtag">CERT/CC SSVC</span></div>
              <span class="ssvcprogress" id="ssvc-progress">0 of 3 answered</span>
            </div>
            <details class="ssvcabout">
              <summary>What are these three questions?</summary>
              <div class="aboutbody">
                <span>They are the official SSVC decision points that describe <b>your deployment</b>, not the vulnerability. They are categories, not a numeric risk score.</span>
                <span>Leave one on <b>Not assessed</b> and PatchTriage stores it as missing, applies the conservative CERT/CC fallback shown under the question, and flags the decision for confirmation.</span>
                <span>Session data is isolated and expires from the server after six hours.</span>
                <a href="https://certcc.github.io/SSVC/howto/deployer_tree/" target="_blank" rel="noopener">Official CERT/CC SSVC Deployer model and definitions ↗</a>
              </div>
            </details>
            <label class="ssvcfield" id="fw-exposure">
              <span class="fieldhead"><span class="fieldnum">1</span><span class="fieldname">System Exposure</span><span class="standardtag">EXP 1.0.1</span></span>
              <span class="fieldq">Who can reach this system?</span>
              <select id="f-exposure"><option value="unknown" selected>Not assessed</option><option value="open">Open</option><option value="controlled">Controlled</option><option value="small">Small</option></select>
              <span class="fieldnow" id="d-exposure"></span>
            </label>
            <label class="ssvcfield" id="fw-mission">
              <span class="fieldhead"><span class="fieldnum">2</span><span class="fieldname">Mission Impact</span><span class="standardtag">MI 2.0.0</span></span>
              <span class="fieldq">What essential work stops if this system fails?</span>
              <select id="f-mission"><option value="unknown" selected>Not assessed</option><option value="degraded">Degraded</option><option value="mef_support_crippled">MEF Support Crippled</option><option value="mef_failure">MEF Failure</option><option value="mission_failure">Mission Failure</option></select>
              <span class="fieldnow" id="d-mission"></span>
            </label>
            <label class="ssvcfield" id="fw-safety">
              <span class="fieldhead"><span class="fieldnum">3</span><span class="fieldname">Safety Impact</span><span class="standardtag">SI 2.0.1</span></span>
              <span class="fieldq">What is the worst credible harm if exploitation succeeds?</span>
              <select id="f-safety"><option value="unknown" selected>Not assessed</option><option value="negligible">Negligible</option><option value="marginal">Marginal</option><option value="critical">Critical</option><option value="catastrophic">Catastrophic</option></select>
              <span class="fieldnow" id="d-safety"></span>
            </label>
            <div class="derived">
              <span class="derivedlabel">Derived · Human Impact <span class="standardtag">HI 2.0.2</span></span>
              <span class="derivedvalue"><b id="d-human">—</b><span id="d-humanpath"></span></span>
              <span class="derivednote">Mission + safety determine Human Impact. Exploitation and Automatable belong to the vulnerability rather than the system and are evaluated per finding.</span>
            </div>
          </div>
          <details class="advanced" id="bodform">
            <summary>Optional context · CISA BOD 26-04 policy and supporting evidence</summary>
            <div class="advcols">
              <div class="advcol">
                <span class="advgroup">CISA BOD 26-04 policy <span class="standardtag">separate from SSVC</span></span>
                <span class="fieldhelp">Separate decision table (<a href="https://certcc.github.io/SSVC/howto/cisa_response/" target="_blank" rel="noopener">cisa:DT_BOD2604:1.0.0</a>) that never changes SSVC; binding only for US federal civilian systems. Publicly Exposed is CISA's question, not SSVC System Exposure; unassessed, it stays unresolved unless Internet exposed is Yes.</span>
                <div class="advfields">
                  <label class="fieldlabel">Applicability<select id="f-bod"><option value="unknown">Not recorded (reference only)</option><option value="required">Required: federal civilian system</option><option value="voluntary">Voluntary adoption</option><option value="not_applicable">Does not apply (reference only)</option></select></label>
                  <label class="fieldlabel">Publicly Exposed (CISA)<select id="f-public"><option value="unknown">Not assessed</option><option value="yes">Yes: reachable by unauthenticated or untrusted users over a public network</option><option value="no">No: not reachable that way</option></select></label>
                </div>
              </div>
              <div class="advcol">
                <span class="advgroup">Supporting context evidence</span>
                <span class="fieldhelp">PatchTriage fields, not SSVC decision points: they never override the three answers above, are recorded with the decision, and are used as a fallback when System Exposure is left unassessed.</span>
                <div class="advfields">
                  <label class="fieldlabel">Criticality<select id="f-criticality"><option value="unknown">Unknown</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
                  <label class="fieldlabel">Internet exposed<select id="f-internet"><option value="unknown">Unknown</option><option value="true">Yes</option><option value="false">No</option></select></label>
                  <label class="fieldlabel">Code reachable<select id="f-reachable"><option value="unknown">Unknown</option><option value="true">Observed / confirmed</option><option value="false">Not reachable</option></select></label>
                  <label class="fieldlabel">Runtime observed<select id="f-runtime"><option value="unknown">Unknown</option><option value="true">Observed at runtime</option><option value="false">Not observed</option></select></label>
                  <label class="fieldlabel">Evidence sources<input type="text" id="f-sources" maxlength="400" placeholder="CMDB, OpenTelemetry, Falco"></label>
                </div>
              </div>
            </div>
          </details>
          <div class="hint">You can leave answers unassessed. Conservative defaults stay flagged until you confirm them.</div>
        </div>
      </section>
</dialog>


<input type="file" id="filepick" class="filehidden" accept=".json">
<dialog id="repodialog"><div class="dialogbody"><h3 id="repo-title">Import a repository</h3><p id="repo-help">PatchTriage fetches a GitHub SPDX SBOM without cloning or executing repository code. Repository access follows the GitHub credentials configured for this deployment.</p><label class="fieldlabel">Repository URL<input type="text" id="repo-url" placeholder="https://github.com/owner/repository"></label><div class="dialogactions"><button class="btn" id="repo-cancel">Cancel</button><button class="btn primary" id="repo-import">Import evidence</button></div></div></dialog>
<dialog id="fleetdialog"><div class="dialogbody"><h3>Import an organization</h3><p>Every recently pushed public repository of the account becomes a target with its GitHub Dependency Graph SBOM attached — the same no-clone, no-execution path as a single repository import. Forks and archived repositories are skipped. Each target starts with the official conservative SSVC defaults; review its context before trusting the decision.</p><label class="fieldlabel">Organization or user URL<input type="text" id="fleet-url" placeholder="https://github.com/your-org"></label><label class="fieldlabel">Repository limit<input type="number" id="fleet-limit" min="1" value="10"></label><div class="dialogactions"><button class="btn" id="fleet-cancel">Cancel</button><button class="btn primary" id="fleet-import">Import repositories</button></div></div></dialog>
<div id="toast" class="toast" role="status" aria-live="polite"></div>
<script>
const SSVC_LABELS=__SSVC_LABELS__;
const HUMAN_IMPACT=__HUMAN_IMPACT__;
let CFG={backends:["rules"],has_ai:false,ai_provider:null};
let selectedTarget=null;const VIEWS=new Map();let booting=true;let renderedView="";
let TARGETS=[];let RESULTS=new Map();let STATUS=new Map();let pickTarget=null;let repoTarget=null;let editingTarget=null;let toastTimer=null;

async function api(method,path,body){
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),method==="GET"?15000:120000);
  const opt={method,headers:{},signal:controller.signal};
  if(body!==undefined){opt.headers["Content-Type"]="application/json";opt.body=JSON.stringify(body);}
  try{
    const response=await fetch(path,opt);
    let payload;
    try{payload=response.status===204?null:await response.json();}
    catch(error){const invalid=new Error("The server returned an unreadable response. Reconnect to check the result.");invalid.status=response.status;invalid.retryable=true;throw invalid;}
    if(!response.ok){const error=new Error((payload&&payload.error)||response.statusText);error.status=response.status;error.retryable=response.status>=500||response.status===429;throw error;}
    return payload;
  }catch(error){if(!error.status)error.retryable=true;throw error;}
  finally{clearTimeout(timer);}
}

function esc(value){return String(value==null?"":value).replace(/[&<>"]/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[ch]));}
function notify(message,error=false){
  const el=document.getElementById("toast");el.textContent=message;el.className="toast show"+(error?" error":"");
  clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.className="toast",3600);
}
function setBusy(){
  document.getElementById("runall").disabled=booting||!TARGETS.some(t=>t.source_file&&!isPending(t.id));
  document.querySelectorAll('[data-action="run"],.retry-run').forEach(el=>{const id=el.dataset.id||el.closest('[data-id]')?.dataset.id;el.disabled=booting||isPending(id);});
}
function isPending(id){return ["queued","running","reconnecting"].includes(STATUS.get(id)?.state);}
function rememberSelection(){try{sessionStorage.setItem("patchtriage-selection",selectedTarget||"");}catch{}}
function selectTarget(id){selectedTarget=id;rememberSelection();renderTargets();renderResults();}
function openTargetForm(){resetForm();document.getElementById("contextdialog").showModal();document.getElementById("f-name").focus();}
function pct(value,total){return value&&total?Math.max(5,Math.round(value/total*100)):0;}

async function loadConfig(){
  CFG=await api("GET","/api/config");
  const labels={rules:"SSVC deterministic",ai:"SSVC + AI explanation",claude:"SSVC + AI explanation",cascade:"SSVC + AI cascade"};
  const available=CFG.backends.length?CFG.backends:["rules"];
  const backendSelect=document.getElementById("backend");
  const backendStatic=document.getElementById("backend-static");
  backendSelect.innerHTML=available.map(b=>`<option value="${esc(b)}">${esc(labels[b]||b)}</option>`).join("");
  const canChoose=available.length>1;
  backendSelect.hidden=!canChoose;
  backendStatic.hidden=canChoose;
  backendStatic.textContent=labels[available[0]]||available[0];
  document.getElementById("privacy-note").hidden=CFG.deployment_mode!=="public";
  const generic=CFG.repository_import&&CFG.repository_import.generic_https_git==="local-osv-scanner";
  const privateGithub=Boolean(CFG.repository_import&&CFG.repository_import.github_private_with_token);
  document.getElementById("repo-title").textContent="Import a repository";
  document.getElementById("repo-help").textContent=generic
    ?`GitHub uses its Dependency Graph SBOM${privateGithub?" with the access granted to the local token":""}. Other HTTPS Git repositories supported by this deployment are cloned into a disposable local directory and statically inspected with OSV-Scanner; repository code and package managers are never executed.`
    :privateGithub
      ?"GitHub repositories use the access granted to this local deployment's token and the Dependency Graph SPDX SBOM API without cloning or executing repository code."
      :"This deployment fetches GitHub SPDX SBOMs through the Dependency Graph API without cloning or executing repository code.";
}
async function loadTargets(){
  TARGETS=await api("GET","/api/targets");
  if(!TARGETS.some(t=>t.id===selectedTarget))selectedTarget=TARGETS[0]?.id||null;
  renderTargets();updateKpis();
}
async function loadSummaries(){
  const summaries=await api("GET","/api/summaries");RESULTS=new Map(summaries.map(summary=>[summary.target_id,summary]));renderResults();
}
async function resumeActiveJobs(){
  // Read jobs before summaries: a run finishing between these requests is
  // either watched below or already present in the committed summaries.
  const jobs=await api("GET","/api/jobs?latest=1");
  await loadSummaries();
  for(const job of jobs){
    if(!TARGETS.some(t=>t.id===job.target_id))continue;
    if(job.state==="failed"){RESULTS.delete(job.target_id);STATUS.set(job.target_id,{state:"failed",error:job.error});}
    else if(job.state==="succeeded"&&job.summary){STATUS.delete(job.target_id);RESULTS.set(job.target_id,job.summary);}
    else if(["queued","running"].includes(job.state)){RESULTS.delete(job.target_id);watchJob(job.target_id,job.job_id);}
  }
  let pending=[];try{pending=JSON.parse(sessionStorage.getItem("patchtriage-queue")||"[]");}catch{}
  if(Array.isArray(pending))for(const item of pending){
    const target=TARGETS.find(t=>t.id===item.id);
    if(target?.source_file&&target.input_revision===item.revision&&!jobs.some(j=>j.target_id===item.id&&j.created_at>=item.queuedAt))enqueue(item.id,item.backend,item.queuedAt);
  }
  renderResults();pumpQueue();
}

function contextTags(target){
  const exposure=target.system_exposure||"unknown",mission=target.mission_impact||"unknown",safety=target.safety_impact||"unknown";
  const tags=[`<span class="tag ${exposure==="open"?"hot":exposure==="unknown"?"warn":""}">EXP ${esc(exposure)}</span>`,`<span class="tag ${mission==="unknown"?"warn":""}">MI ${esc(mission)}</span>`,`<span class="tag ${safety==="unknown"?"warn":""}">SI ${esc(safety)}</span>`];
  const bod=target.bod2604_applicability||"unknown";
  if(bod==="required"||bod==="voluntary")tags.push(`<span class="tag">BOD 26-04 ${bod} · PE ${esc(target.publicly_exposed||"unknown")}</span>`);
  if(target.demo)tags.push('<span class="tag demo">offline demo</span>');
  return tags.join("");
}
function renderTargets(){
  const list=document.getElementById("targetlist");
  if(!TARGETS.length){list.innerHTML='<div class="hint">Your systems will appear here.</div>';return;}
  list.innerHTML=TARGETS.map(target=>{
    const status=STATUS.get(target.id),result=RESULTS.get(target.id);
    const label=status?({queued:"Waiting to run",running:"Assessing…",reconnecting:"Reconnecting…",disconnected:"Connection interrupted",failed:"Assessment failed"}[status.state]||status.state):result?`${result.total} findings · ${result.top_ssvc_decision||"No findings"}`:target.source_file?"Ready to run":"Add evidence to continue";
    return `<article class="target ${target.id===selectedTarget?"selected":""}" data-id="${esc(target.id)}"><button class="targetselect" data-action="select" aria-pressed="${target.id===selectedTarget}"><span class="targetname">${esc(target.name)}</span><span class="targetmeta">${esc(target.demo?"Bundled offline evidence":target.source_name||"No evidence attached")}</span><span class="targetstate ${status?.state==="failed"?"failed":""}">${esc(label)}</span></button></article>`;
  }).join("");
  setBusy();
}

function updateKpis(){
  const values=[...RESULTS.entries()].filter(([id])=>!STATUS.has(id)).map(([,r])=>r);
  const totalFindings=values.reduce((n,r)=>n+r.total,0);
  const verified=values.reduce((n,r)=>n+r.audit_verified,0);
  document.getElementById("k-targets").textContent=TARGETS.length;
  document.getElementById("k-kev").textContent=values.reduce((n,r)=>n+r.kev,0);
  document.getElementById("k-immediate").textContent=values.reduce((n,r)=>n+r.outcomes.immediate,0);
  document.getElementById("k-audit").textContent=totalFindings?Math.round(verified/totalFindings*100)+"%":"—";
  const points=values.reduce((n,r)=>n+((r.decision_quality||{}).points_total||0),0);
  const authoritative=values.reduce((n,r)=>n+((r.decision_quality||{}).authoritative||0),0);
  document.getElementById("k-authoritative").textContent=points?Math.round(authoritative/points*100)+"%":"—";
}
function compareBlock(summary){
  const c=summary.comparison;if(!c)return `<div class="emptyresult"><b>No findings to compare</b><span>${esc(summary.result_message||"The attached evidence contained no vulnerability records.")}</span></div>`;
  const maximum=Math.max(1,c.kev_total);const o=c.outcome||{};
  const coverage=c.kev_total?`${o.kev_coverage_pct}%`:"n/a";
  const urgent=c.urgent&&c.urgent.total?`${o.urgent_coverage_pct}%`:"n/a";
  return `<div class="microtitle">Outcome at a ${c.k}-finding review budget</div>
    <div class="outcomegrid">
      <div class="outcomemicro"><b>${esc(o.review_reduction_pct==null?"n/a":o.review_reduction_pct+"%")}</b><span>smaller first-pass queue</span></div>
      <div class="outcomemicro"><b>${esc(coverage)}</b><span>KEV coverage</span></div>
      <div class="outcomemicro"><b>${esc(urgent)}</b><span>SSVC urgent coverage</span></div>
    </div>
    <div class="microtitle">Known-exploited findings surfaced</div>
    <div class="barrow"><span>CVSS only</span><div class="track"><div class="fill" style="width:${pct(c.kev.cvss,maximum)}%"></div></div><span class="barvalue">${c.kev.cvss}/${c.kev_total}</span></div>
    <div class="barrow"><span>EPSS only</span><div class="track"><div class="fill epss" style="width:${pct(c.kev.epss,maximum)}%"></div></div><span class="barvalue">${c.kev.epss}/${c.kev_total}</span></div>
    <div class="barrow"><span>KEV first</span><div class="track"><div class="fill epss" style="width:${pct(c.kev.kev,maximum)}%"></div></div><span class="barvalue">${c.kev.kev}/${c.kev_total}</span></div>
    <div class="barrow"><span>SSVC context</span><div class="track"><div class="fill pt" style="width:${pct(c.kev.ssvc,maximum)}%"></div></div><span class="barvalue">${c.kev.ssvc}/${c.kev_total}</span></div>
    <div class="comparefoot">KEV-first is now an explicit baseline. SSVC may rank a KEV below another finding when your exposure and human impact justify a different deployment action.</div>`;
}
function explainBlock(summary){
  const x=summary.explanation;if(!x)return `<div class="emptyresult"><b>${summary.result_state==="coverage_incomplete"?"Coverage incomplete":summary.result_state==="no_findings"?"No findings reported":"No decision explanation available"}</b><span>${esc(summary.result_message||"Inspect the full report for input and processing details.")}</span></div>`;
  const s=x.ssvc||{};const pointKeys=[["exploitation","Exploitation"],["system_exposure","System Exposure"],["automatable","Automatable"],["human_impact","Human Impact"]];
  const flow=pointKeys.map(([key,label])=>{const p=s[key]||{};return `<div class="factor"><span>${esc(label)}</span><b>${esc(p.label||"Unknown")}</b><small>${esc(p.confidence||"low")} confidence · ${esc(p.source||"missing")}</small></div>`;}).join("");
  const cvss=x.cvss==null?"Not available":Number(x.cvss).toFixed(1);
  const epss=x.epss==null?"Not available":`${(Number(x.epss)*100).toFixed(1)}%`;
  const kevStatus=(x.retrieval_status||{}).kev;const kevLabel=kevStatus==="failed"?"Lookup failed":x.kev?"Listed":kevStatus==="not_listed"?"Not listed":"Not confirmed";
  const signals=[["CVSS",cvss],["EPSS (30 day)",epss],["CISA KEV",kevLabel],["Fix",x.has_fix?"Available":"Not supplied"]].map(([label,value])=>`<div class="signal"><span>${esc(label)}</span><b>${esc(value)}</b></div>`).join("");
  const marks={confirmed:"✓",attention:"!",unknown:"?","not-observed":"–"};
  const checks=(x.checks||[]).map(item=>`<li><span class="evidenceicon ${esc(item.status)}">${marks[item.status]||"·"}</span><span><strong>${esc(item.label)}</strong><small>${esc(item.value)}</small></span></li>`).join("");
  const advisories=(x.advisories||[]).map(a=>a.url
    ?`<a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.source.toUpperCase())} · ${esc(a.advisory_id)} ↗</a>`
    :`<span>${esc(a.source.toUpperCase())} · ${esc(a.advisory_id)}</span>`).join("");
  return `<div class="microtitle">Why ${esc(s.decision_label||x.outcome_label)}?</div>
    <div class="basis">${esc(x.basis)}</div>
    <div class="ssvcflow">${flow}</div>
    <div class="decisionline"><span>SSVC Deployer · ${esc(s.model||"")}</span><b>${esc(s.decision_label||"Unknown")}</b></div>
    <div class="decisionnote"><b>Categorical outcome — no aggregate SSVC score.</b> Supporting signals remain visible. Inside the same outcome, SSVC decision points are compared first, followed by EPSS and CVSS tie-breakers; none are added together into a score.</div>
    <div class="signalgrid">${signals}</div>
    ${bodBlock(x)}
    ${(x.needs_confirmation||[]).length?`<div class="confirmbar">Confirm inferred inputs: ${esc(x.needs_confirmation.map(v=>String(v).replaceAll("_"," ")).join(", "))}. Conservative defaults remain active until reviewed.</div>`:""}
    ${checks?`<ul class="evidence" aria-label="Decision evidence checklist">${checks}</ul>`:""}
    ${advisories?`<div class="advisoryline">${advisories}</div>`:""}`;
}
function ssvcInputSelect(field,item){
  const point=item[field]||{},override=(item.override||{})[field]||"auto";
  const choices=field==="exploitation"
    ?[["auto",`Use evidence/default (${point.label||"Unknown"})`],["none","None"],["public_poc","Public PoC"],["active","Active"]]
    :[["auto",`Use evidence/default (${point.label||"Unknown"})`],["no","No"],["yes","Yes"]];
  return `<select data-field="${field}" aria-label="${field} for ${esc(item.vuln_id)}">${choices.map(([value,label])=>`<option value="${value}" ${override===value?"selected":""}>${esc(label)}</option>`).join("")}</select><span class="inputsource">${esc(point.source||"No source")} · ${esc(point.confidence||"low")} confidence</span>`;
}
function ssvcInputBlock(summary){
  const inputs=summary.ssvc_inputs||[];if(!inputs.length)return "";
  const total=summary.ssvc_inputs_total==null?inputs.length:summary.ssvc_inputs_total;
  const review=summary.ssvc_inputs_review_total==null?inputs.filter(item=>item.needs_review).length:summary.ssvc_inputs_review_total;
  const visible=inputs.slice(0,(CFG.limits&&CFG.limits.ssvc_review_rows)||250);
  const rows=visible.map(item=>`<tr data-key="${esc(item.finding_key)}" data-exploitation="${esc((item.override||{}).exploitation||"auto")}" data-automatable="${esc((item.override||{}).automatable||"auto")}">
    <td><b class="cve">${esc(item.vuln_id)}</b><span class="inputsource">${esc(item.package)}</span></td>
    <td>${ssvcInputSelect("exploitation",item)}</td>
    <td>${ssvcInputSelect("automatable",item)}</td>
    <td>${item.needs_review?'<span class="reviewflag">Review requested</span>':'Confirmed / evidence-backed'}</td>
  </tr>`).join("");
  return `<details class="ssvcinputreview" open><summary>Review vulnerability-specific SSVC inputs · ${review} need confirmation</summary>
    <p>CERT/CC defines Exploitation and Automatable per vulnerability. PatchTriage uses authoritative evidence or the official conservative default; select a value only when an analyst can confirm it.</p>
    ${total>visible.length?`<p>Showing the highest-priority ${visible.length} of ${total} findings. Only changed rows are submitted; use the CLI for bulk review.</p>`:""}
    <table class="ssvcinputtable"><thead><tr><th>Finding</th><th>Exploitation (E)</th><th>Automatable (A)</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="ssvcinputactions"><button class="btn primary small save-ssvc-inputs">Save inputs and rerun</button></div>
  </details>`;
}
function reportFilename(summary){return "patchtriage-"+(String(summary.name||summary.target_id).toLowerCase().replace(/[^a-z0-9._-]+/g,"-").replace(/^-+|-+$/g,"").slice(0,60)||"report")+".html";}
const OUTCOME_ORDER=[["immediate","Immediate","Act now · example local SLA 3 days"],["out_of_cycle","Out-of-Cycle","Next opportunity · example SLA 14 days"],["scheduled","Scheduled","Normal maintenance · example SLA 30 days"],["defer","Defer","Monitor · example review at 90 days"]];
const OUTCOME_COLOR={immediate:"var(--c-immediate)",out_of_cycle:"var(--c-outofcycle)",scheduled:"var(--c-scheduled)",defer:"var(--c-defer)"};
const OUTCOME_KEY={"Immediate":"immediate","Out-of-Cycle":"out_of_cycle","Scheduled":"scheduled","Defer":"defer"};
function donutSvg(outcomes,size,caption){
  const total=OUTCOME_ORDER.reduce((n,[k])=>n+(outcomes[k]||0),0),stroke=Math.max(6,Math.round(size*.085)),r=(size-stroke)/2-2,cx=size/2,cy=size/2;
  const circ=2*Math.PI*r,gap=OUTCOME_ORDER.filter(([k])=>outcomes[k]>0).length>1?4:0;let offset=0;
  const segs=total?OUTCOME_ORDER.filter(([k])=>outcomes[k]).map(([k,label])=>{
    const n=outcomes[k],len=Math.max(0,n/total*circ-gap);
    const seg=`<circle class="seg" cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${OUTCOME_COLOR[k]}" stroke-width="${stroke}" stroke-dasharray="${len} ${circ-len}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})"><title>${esc(label)}: ${n} of ${total} (${Math.round(n/total*100)}%)</title></circle>`;
    offset+=n/total*circ;return seg;
  }).join(""):`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--line)" stroke-width="${stroke}"></circle>`;
  const text=OUTCOME_ORDER.map(([k,label])=>`${label} ${outcomes[k]||0}`).join(", ");
  return `<svg class="donut" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="${esc(caption)}: ${esc(text)}">${segs}${size>=100?`<text class="donutlabel" x="${cx}" y="${cy+3}" text-anchor="middle">${total}</text><text class="donutsub" x="${cx}" y="${cy+20}" text-anchor="middle">findings</text>`:`<text class="donutsub" x="${cx}" y="${cy+4}" text-anchor="middle">${total}</text>`}</svg>`;
}
function renderOutcomeSummary(){
  const el=document.getElementById("outcomesummary");if(!el)return;
  const totals={immediate:0,out_of_cycle:0,scheduled:0,defer:0};
  RESULTS.forEach(r=>OUTCOME_ORDER.forEach(([k])=>totals[k]+=((r.outcomes||{})[k]||0)));
  const total=Object.values(totals).reduce((a,b)=>a+b,0);
  const rows=OUTCOME_ORDER.map(([k,label,meaning])=>`<div class="outcomerow"><div class="name"><i style="background:${OUTCOME_COLOR[k]}" aria-hidden="true"></i>${esc(label)}</div><div class="count">${totals[k]}<small>${total?Math.round(totals[k]/total*100)+"%":"—"}</small></div><div class="meaning">${esc(meaning)}</div></div>`).join("");
  el.innerHTML=`${donutSvg(totals,112,"SSVC outcomes across all assessed targets")}<div><div class="microtitle">SSVC outcomes across ${RESULTS.size} assessed target${RESULTS.size===1?"":"s"} · ${total} findings</div><div class="outcomerows">${rows}</div></div>`;
}
function breakdownBlock(summary){
  const o=summary.outcomes||{};const total=OUTCOME_ORDER.reduce((n,[k])=>n+(o[k]||0),0);if(!total)return "";
  const chips=OUTCOME_ORDER.map(([k,label])=>`<span class="chip"><i style="background:${OUTCOME_COLOR[k]}" aria-hidden="true"></i>${esc(label)} <b>${o[k]||0}</b></span>`).join("");
  return `<div class="breakdown">${donutSvg(o,72,"SSVC outcomes for "+summary.name)}<div><div class="microtitle">Outcome breakdown · ${total} findings</div><div class="chips">${chips}</div></div></div>`;
}
const TREE_LEVELS=[
  ["exploitation","Exploitation",[["none","None"],["public_poc","Public PoC"],["active","Active"]]],
  ["system_exposure","System Exposure",[["small","Small"],["controlled","Controlled"],["open","Open"]]],
  ["automatable","Automatable",[["no","No"],["yes","Yes"]]],
  ["human_impact","Human Impact",[["low","Low"],["medium","Medium"],["high","High"],["very_high","Very High"]]]];
function treeSvg(path){
  const W=1000,H=196,nodeW=128,nodeH=28,top=40,colX=[16,188,358,528,698,866],leafW=126,P=path.points||{};
  const ys=n=>Array.from({length:n},(_,i)=>top+(H-top-12)*(i+0.5)/n);
  let edges="",nodes="",prev={x:colX[0]+nodeW,y:top+(H-top-12)/2};
  const clip=(v,n)=>{v=String(v||"");return v.length>n?v.slice(0,n-1)+"…":v;};
  // The selected edge draws in once per column so a new finding reads left to right.
  const onEdge=level=>` pathLength="1" style="--step:${level}"`;
  nodes+=`<g class="node root"><rect x="${colX[0]}" y="${prev.y-28}" width="${nodeW}" height="56" rx="8"></rect><text class="cve" x="${colX[0]+14}" y="${prev.y-4}">${esc(clip(path.vuln_id,17))}</text><text class="asset" x="${colX[0]+14}" y="${prev.y+15}">${esc(clip(path.asset,19))}</text><title>${esc(path.asset)} · ${esc(path.package)} ${esc(path.version)} · ${esc(path.vuln_id)}</title></g>`;
  const heads=["Finding","Exploitation","System Exposure","Automatable","Human Impact","SSVC outcome"].map((h,i)=>`<text class="colhead" x="${colX[i]+(i?nodeW/2:14)}" y="18" text-anchor="${i?"middle":"start"}">${h}</text>`).join("");
  let hiYs=[];
  TREE_LEVELS.forEach(([key,,values],level)=>{
    const x=colX[level+1],y=ys(values.length),chosen=(P[key]||{}).value,assumed=(P[key]||{}).needs_confirmation;let next=null;
    values.forEach(([value,label],i)=>{
      const on=value===chosen,flag=on&&assumed;
      edges+=`<path class="edge${on?" on":""}"${on?onEdge(level):""} d="M${prev.x} ${prev.y} C ${prev.x+30} ${prev.y}, ${x-30} ${y[i]}, ${x} ${y[i]}"></path>`;
      nodes+=`<g class="node${on?" on":""}${flag?" assumed":""}"><rect x="${x}" y="${y[i]-nodeH/2}" width="${nodeW}" height="${nodeH}" rx="7"></rect><text x="${x+nodeW/2}" y="${y[i]+4.5}" text-anchor="middle">${esc(label)}</text>${flag?`<g class="assumedbadge"><circle cx="${x+nodeW}" cy="${y[i]-nodeH/2}" r="8"></circle><text x="${x+nodeW}" y="${y[i]-nodeH/2+4}" text-anchor="middle">?</text></g>`:""}<title>${esc(label)}${on?` · ${(P[key]||{}).source||""}${assumed?" · conservative default, needs confirmation":""}`:""}</title></g>`;
      if(on)next={x:x+nodeW,y:y[i]};
    });
    if(level===3)hiYs=y;
    prev=next||prev;
  });
  (path.branches||[]).forEach((branch,i)=>{
    const on=branch.human_impact===(P.human_impact||{}).value,k=branch.decision,x=colX[5],y=hiYs[i],sx=colX[4]+nodeW;
    edges+=`<path class="edge${on?" on final":""}"${on?onEdge(4):""} data-outcome="${esc(k)}" d="M${sx} ${y} L ${x} ${y}"></path>`;
    nodes+=`<g class="leaf ${on?"on":"off"}" data-outcome="${esc(k)}"><rect x="${x}" y="${y-nodeH/2}" width="${leafW}" height="${nodeH}" rx="7"></rect><circle class="dot" cx="${x+14}" cy="${y}" r="3.5"></circle><text x="${x+26}" y="${y+4.5}">${esc(branch.decision_label)}</text><title>Human Impact ${esc(branch.human_impact_label)} → ${esc(branch.decision_label)}</title></g>`;
  });
  const grid=`<defs><pattern id="treegrid" width="16" height="16" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1"></circle></pattern></defs><rect class="grid" width="${W}" height="${H}" fill="url(#treegrid)"></rect>`;
  return `<svg class="tree" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(pathSentencePlain(path))}">${grid}${heads}${edges}${nodes}</svg>`;
}
function pathSentencePlain(path){const P=path.points||{};return `${path.asset}: ${path.vuln_id} in ${path.package} ${path.version} — Exploitation ${(P.exploitation||{}).label}, System Exposure ${(P.system_exposure||{}).label}, Automatable ${(P.automatable||{}).label}, Human Impact ${(P.human_impact||{}).label} → ${path.decision_label}`;}
function pathDetail(path){
  const P=path.points||{};
  const sources=TREE_LEVELS.map(([key,label])=>{const point=P[key]||{};return `<div class="pathsource ${point.needs_confirmation?"assumed":""}"><span class="sourcekey">${esc(label)}</span><strong>${esc(point.label||"Unknown")}${point.needs_confirmation?" ?":""}</strong><span class="sourcevia">${esc(point.source||"Source unavailable")}</span></div>`;}).join("");
  const evidence=(path.evidence||[]).map(e=>{const more=e.more?` (+${esc(e.more)} more in the report)`:"";return e.url?`<a href="${esc(e.url)}" target="_blank" rel="noopener">${esc(e.source)} · ${esc(e.label)} ↗${more}</a>`:`<span>${esc(e.source)} · ${esc(e.label)}${more}</span>`;}).join("");
  return `<div class="treecanvas">${treeSvg(path)}</div>
    <ul class="treelegend" aria-label="Legend"><li><i class="swatch path" aria-hidden="true"></i>Selected path</li><li><i class="swatch assumed" aria-hidden="true">?</i>Assumed input, needs confirmation</li><li><i class="swatch alt" aria-hidden="true"></i>Other outcomes vary Human Impact</li></ul>
    <div class="pathsources">${sources}</div>
    <div class="pathcontext"><span>Human Impact: <b>${esc((P.mission_impact||{}).label)}</b> mission + <b>${esc((P.safety_impact||{}).label)}</b> safety</span>${path.version_source?`<span class="reviewflag">Version inferred: ${esc(path.version_source)}</span>`:""}${path.bod2604?`<span class="policyhint">BOD 26-04: ${esc(path.bod2604.label)}${path.bod2604.applied?"":" · reference only"}</span>`:""}</div>
    ${evidence?`<div class="evidencelinks" aria-label="Vulnerability evidence">${evidence}</div>`:""}`;
}

function treeBlock(summary){
  const paths=summary.decision_paths||[];
  if(!paths.length)return `<div class="emptyresult"><b>${summary.total?"No decision path available":"No findings reported"}</b><span>${esc(summary.result_message||"Review coverage and evidence in the full report.")}</span></div>`;
  const selected=Math.min(VIEWS.get(summary.target_id)?.finding||0,paths.length-1);
  const options=paths.map((path,i)=>`<option value="${i}" ${i===selected?"selected":""}>${esc(path.decision_label)} · ${esc(path.vuln_id)} · ${esc(path.package)} ${esc(path.version)}</option>`).join("");
  return `<section class="treeview" aria-label="Decision path · why each finding reached its SSVC outcome">
    <div class="treepick"><label class="fieldlabel">Finding<select class="treeselect" aria-label="Finding to explain for ${esc(summary.name)}">${options}</select></label>${summary.decision_paths_truncated?`<span class="hint">First ${paths.length} findings; all in report.</span>`:""}</div>
    <div class="treebody">${pathDetail(paths[selected])}</div></section>`;
}

// Overview: every finding's route through the Deployer tree at once. The
// browser only counts the engine's values; it never decides an outcome.
const FLOW_LEVELS=[...TREE_LEVELS,["decision","SSVC outcome",[["defer","Defer"],["scheduled","Scheduled"],["out_of_cycle","Out-of-Cycle"],["immediate","Immediate"]]]];
const FLOW_LABEL=Object.fromEntries(FLOW_LEVELS.map(([key,,values])=>[key,Object.fromEntries(values)]));
function overviewRows(summary){
  if(Array.isArray(summary.overview))return summary.overview;
  // Summaries stored before the overview existed: rebuild from decision paths.
  return (summary.decision_paths||[]).map((p,i)=>{const P=p.points||{};return {finding_key:p.finding_key,vuln_id:p.vuln_id,package:p.package,version:p.version,asset:p.asset,decision:p.decision,decision_label:p.decision_label,
    exploitation:(P.exploitation||{}).value,system_exposure:(P.system_exposure||{}).value,automatable:(P.automatable||{}).value,human_impact:(P.human_impact||{}).value,
    assumed:TREE_LEVELS.map(([k])=>k).filter(k=>(P[k]||{}).needs_confirmation),path:i};});
}
function matchesFilter(row,filter){return Object.entries(filter||{}).every(([k,v])=>row[k]===v);}
function flowSvg(rows,filter){
  const W=1000,top=34,bottom=8,nodeW=132,minH=24,gap=10,colX=[0,217,434,651,868],maxPlot=278,base=4*minH+3*gap;
  // Every finding passes through each column, so the four-value columns are the
  // tallest; size the chart to them instead of leaving empty space for few findings.
  const scale=rows.length?Math.min(16,(maxPlot-base)/rows.length):0,plotH=base+rows.length*scale,H=top+plotH+bottom,active=Object.keys(filter||{}).length>0;
  const nodes={};let svg="";
  FLOW_LEVELS.forEach(([key,label,values],c)=>{
    const counts=values.map(([v])=>rows.filter(r=>r[key]===v).length);
    const heights=counts.map(n=>minH+n*scale),colH=heights.reduce((a,b)=>a+b,0)+gap*(values.length-1);
    let y=top+(plotH-colH)/2;
    values.forEach(([v],i)=>{nodes[key+":"+v]={x:colX[c],y,h:heights[i],n:counts[i]};y+=heights[i]+gap;});
    svg+=`<text class="colhead" x="${colX[c]+nodeW/2}" y="16" text-anchor="middle">${esc(label)}</text>`;
  });
  // One ribbon per (from, to, outcome), stacked inside each node in outcome order.
  const ribbons=(subset,cls)=>{let out="";const off={};
    for(let c=0;c<FLOW_LEVELS.length-1;c++){
      const [ka,,va]=FLOW_LEVELS[c],[kb,,vb]=FLOW_LEVELS[c+1];
      va.forEach(([a])=>vb.forEach(([b])=>OUTCOME_ORDER.forEach(([o,olabel])=>{
        const n=subset.filter(r=>r[ka]===a&&r[kb]===b&&r.decision===o).length;if(!n)return;
        const p=nodes[ka+":"+a],q=nodes[kb+":"+b],w=n*scale,so=off["o"+ka+a]||0,ti=off["i"+kb+b]||0;
        off["o"+ka+a]=so+w;off["i"+kb+b]=ti+w;
        const y1=p.y+(p.h-p.n*scale)/2+so,y2=q.y+(q.h-q.n*scale)/2+ti,x1=p.x+nodeW,x2=q.x,mx=(x1+x2)/2;
        const title=`${n} finding${n===1?"":"s"}: ${FLOW_LABEL[ka][a]} → ${FLOW_LABEL[kb][b]} · ${olabel}`;
        out+=`<path class="ribbon ${cls}" data-outcome="${esc(o)}" data-flow='${esc(JSON.stringify({[ka]:a,[kb]:b,decision:o}))}' tabindex="${cls==="base"?0:-1}" role="button" aria-label="${esc(title)} · filter the list" d="M${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2} L ${x2} ${y2+w} C ${mx} ${y2+w}, ${mx} ${y1+w}, ${x1} ${y1+w} Z"><title>${esc(title)}</title></path>`;
      })));
    }
    return out;};
  svg+=ribbons(rows,active?"base dim":"base");
  if(active)svg+=ribbons(rows.filter(r=>matchesFilter(r,filter)),"hit");
  FLOW_LEVELS.forEach(([key,,values],c)=>values.forEach(([v,label])=>{
    const node=nodes[key+":"+v],leaf=key==="decision",on=active&&filter[key]===v,hits=active?rows.filter(r=>r[key]===v&&matchesFilter(r,filter)).length:node.n;
    const title=`${FLOW_LABEL[key][v]}: ${node.n} finding${node.n===1?"":"s"}${node.n?" · filter the list":""}`,x=colX[c],mid=node.y+node.h/2;
    svg+=`<g class="flownode${leaf?" leaf":""}${node.n?"":" empty"}${on?" on":""}"${leaf?` data-outcome="${esc(v)}"`:""}${node.n?` data-flow='${esc(JSON.stringify({[key]:v}))}' tabindex="0" role="button"`:""} aria-label="${esc(title)}"><rect x="${x}" y="${node.y}" width="${nodeW}" height="${node.h}" rx="6"></rect>${leaf?`<circle class="dot" cx="${x+12}" cy="${mid}" r="3.5"></circle>`:""}<text x="${x+(leaf?22:10)}" y="${mid+4.5}">${esc(label)}</text><text class="count" x="${x+nodeW-10}" y="${mid+4.5}" text-anchor="end">${active&&hits!==node.n?`${hits}/`:""}${node.n}</text><title>${esc(title)}</title></g>`;
  }));
  return `<svg class="flowchart" viewBox="0 0 ${W} ${H}" role="group" aria-label="Decision flow of ${rows.length} findings through the SSVC Deployer tree">${svg}</svg>`;
}
function overviewBlock(summary){
  const rows=overviewRows(summary);
  if(!rows.length)return `<div class="emptyresult"><b>${summary.result_state==="coverage_incomplete"?"Coverage incomplete":summary.total?"No decision path available":"No findings reported"}</b><span>${esc(summary.result_message||"Review coverage and evidence in the full report.")}</span></div>`;
  const filter=VIEWS.get(summary.target_id)?.filter||{},active=Object.keys(filter).length>0,shown=rows.filter(r=>matchesFilter(r,filter));
  const filterText=Object.entries(filter).map(([k,v])=>`${FLOW_LEVELS.find(l=>l[0]===k)[1]}: ${FLOW_LABEL[k][v]}`).join(", ");
  const cell=(row,key)=>`${esc(FLOW_LABEL[key][row[key]]||row[key]||"—")}${(row.assumed||[]).includes(key)?' <span class="assumedmark" title="Conservative default; needs confirmation">?</span>':""}`;
  const body=shown.map(row=>`<tr><td><span class="outcomepill ${esc(String(row.decision).replaceAll("_","-"))}"><i style="background:${OUTCOME_COLOR[row.decision]||"var(--c-defer)"}" aria-hidden="true"></i>${esc(row.decision_label)}</span></td>
    <td>${row.path!=null?`<button class="textbutton openpath" data-path="${esc(row.path)}" title="Open this finding's decision path">${esc(row.vuln_id)}</button>`:`<span class="cve">${esc(row.vuln_id)}</span>`}${row.kev?' <span class="tag hot">KEV</span>':""}</td>
    <td>${esc(row.package)} <span class="hint">${esc(row.version||"")}</span></td><td class="hint">${esc(row.asset||"")}</td>
    <td>${cell(row,"exploitation")}</td><td>${cell(row,"system_exposure")}</td><td>${cell(row,"automatable")}</td><td>${cell(row,"human_impact")}</td></tr>`).join("");
  return `<section class="overview" aria-label="All findings at a glance">
    <div class="overviewhead"><h3>How ${rows.length} finding${rows.length===1?"":"s"} reached their outcome</h3><span>Ribbon width is the number of findings; color is the SSVC outcome. Select a box or ribbon to filter the list.</span></div>
    <div class="treecanvas flowcanvas">${flowSvg(rows,filter)}</div>
    <div class="overviewbar" aria-live="polite"><span>${active?`Showing ${shown.length} of ${rows.length} · ${esc(filterText)}`:`All ${rows.length} findings, most urgent first`}</span>${active?'<button class="btn small clearflow">Clear filter</button>':""}</div>
    ${summary.overview_truncated?`<p class="hint">Showing the highest-priority ${rows.length} of ${summary.total} findings; the full report lists every finding.</p>`:""}
    <div class="queuewrap"><table class="queuetable overviewtable"><thead><tr><th>SSVC outcome</th><th>Finding</th><th>Package</th><th>Asset</th><th>Exploitation</th><th>Exposure</th><th>Automatable</th><th>Human Impact</th></tr></thead><tbody>${body}</tbody></table></div>
    <ul class="treelegend" aria-label="Legend"><li><i class="swatch assumed" aria-hidden="true">?</i>Assumed input, needs confirmation</li><li>Select a CVE to open its decision path</li></ul>
  </section>`;
}

const OBLIGATIONS={remediate:"Remediate",remediate_at_next_major_upgrade:"Remediate at next major upgrade",forensic_triage:"Forensic triage"};
const RULES={ssvc_only:"SSVC workflow (BOD not applied)",bod_maximum:"BOD 26-04 maximum",workflow_target_stricter:"Workflow target is stricter",bod_fix_on_upgrade:"BOD: fix on system upgrade",bod_unresolved_provisional:"Provisional: BOD inputs unresolved"};
function bodCell(b){
  if(!b)return "—";
  const provisional=b.status!=="resolved";
  return `<span class="bodcell ${b.applied?"":"reference"}"><b>${esc(b.label)}</b>${provisional?` <span class="reviewflag">provisional · ${esc(b.unresolved_findings)} unresolved</span>`:""}${b.forensic_triage&&!/forensic/i.test(b.label)?' <span class="kindtag mitigate">Forensic triage</span>':""}<span class="cves">${b.applied?esc(b.applicability==="required"?"Required":"Voluntary"):"Reference only"}</span></span>`;
}
function effectiveCell(item){
  if(!item.effective_rule)return "—";
  const days=item.effective_deadline_days==null?"No numeric deadline":`≤ ${esc(item.effective_deadline_days)} days`;
  const extra=(item.obligations||[]).filter(o=>o!=="remediate").map(o=>OBLIGATIONS[o]||o);
  return `<b class="num">${days}</b><span class="cves">${esc(RULES[item.effective_rule]||item.effective_rule)}${extra.length?" · also: "+esc(extra.join(", ")):""}</span>`;
}
function policyMetric(p){
  if(!p||!p.evaluated)return "";
  const scope=p.applied?"applied":"reference only";
  return `<span class="metric ${p.unresolved?"alert":""}">BOD 26-04 ${scope}: ${p.resolved}/${p.evaluated} resolved${p.unresolved?`, ${p.unresolved} unresolved`:""}${p.forensic_triage?`, ${p.forensic_triage} forensic triage`:""}</span>`;
}
function bodBlock(x){
  const b=x.bod2604,e=x.effective;if(!b)return "";
  const names={in_kev:"In KEV",publicly_exposed:"Publicly Exposed",automatable:"Automatable",technical_impact:"Technical Impact"};
  const inputs=Object.entries(b.inputs||{}).map(([key,p])=>`<div class="factor"><span>${esc(names[key]||key)}</span><b>${p.resolved?esc(String(p.value).replace(/^./,c=>c.toUpperCase())):"Unresolved"}</b><small>${esc(p.source)}${p.defaulted?" · CISA default":""}</small><small>${esc(p.basis)}</small></div>`).join("");
  const outcome=b.status==="resolved"?esc(b.outcome_label):`Unresolved · provisional ${esc(b.provisional_label)}`;
  const obligations=(b.obligations||[]).map(o=>OBLIGATIONS[o]||o).join(", ");
  return `<div class="bodpanel"><div class="microtitle">CISA BOD 26-04 · separate policy result</div>
    <div class="decisionline"><span>${esc(b.policy)} · ${esc(b.applied?b.applicability:"reference only")}</span><b>${outcome}</b></div>
    <div class="ssvcflow">${inputs}</div>
    <div class="decisionnote"><b>${esc(b.definition)}</b> Obligations: ${esc(obligations)}. ${esc(b.applicability_note)}</div>
    ${b.status!=="resolved"?`<div class="confirmbar">Confirm ${esc((b.unresolved_inputs||[]).map(v=>names[v]||v).join(", "))} to resolve the BOD outcome. Candidates: ${esc((b.candidate_outcomes||[]).join(", "))}.</div>`:""}
    ${e?`<div class="decisionnote"><b>Effective action · ${esc(RULES[e.rule]||e.rule)}.</b> ${esc(e.explanation)}</div>`:""}
    <div class="decisionnote">Clock: ${esc(b.deadline_anchor)}${b.kev_date_added?` KEV added ${esc(b.kev_date_added)}.`:""}${b.kev_due_date?` KEV catalog due date ${esc(b.kev_due_date)}.`:""} PatchTriage does not compute an absolute due date because the agency identification date is not recorded.</div>
  </div>`;
}
function queueBlock(summary){
  const queue=summary.action_queue||[];if(!queue.length)return "";
  const rows=queue.map((item,index)=>{
    const label=item.outcome_label||"Unknown",cls=String(label).toLowerCase().replaceAll(" ","-");
    const cves=item.cves||[],more=Math.max(0,(item.finding_count||cves.length)-cves.length);
    const kind=item.kind==="mitigate"?'<span class="kindtag mitigate">No fix</span>':"";
    return `<tr><td class="num">${index+1}</td><td><span class="outcomepill ${esc(cls)}"><i aria-hidden="true"></i>${esc(label)}</span></td>
      <td>${kind}${esc(item.summary)}<span class="cves"><span class="cve">${esc(cves.join(", "))}</span>${more?` and ${more} more`:""}</span></td>
      <td class="num">${item.kev_count?`${esc(item.kev_count)} KEV`:"—"}</td><td class="num">${esc(item.finding_count)}</td>
      <td class="num">${item.deadline_days==null?"—":`≤ ${esc(item.deadline_days)} days`}</td>
      <td>${bodCell(item.bod2604)}</td><td>${effectiveCell(item)}</td></tr>`;}).join("");
  return `<details class="actionqueue" open><summary>Action queue · ${queue.length}${summary.action_queue_truncated?"+":""} package action${queue.length===1?"":"s"}, highest SSVC outcome first</summary>
    <p>One row per package change. The outcome is the most urgent SSVC Deployer outcome among the findings it closes. “Workflow target” is PatchTriage's configurable example timeline, not an SSVC or regulatory deadline.${summary.action_queue_truncated?" Only the first actions are listed here; the full report has every action.":""}</p>
    <div class="queuewrap"><table class="queuetable"><thead><tr><th>#</th><th>SSVC outcome</th><th>Action</th><th>KEV</th><th>Findings</th><th>Workflow target</th><th>BOD 26-04</th><th>Effective</th></tr></thead><tbody>${rows}</tbody></table></div>
  </details>`;
}
function renderResult(summary){
  const hasFindings=summary.total>0,coverage=summary.source?.coverage_status||"unknown";
  const outcome=hasFindings?(summary.top_ssvc_decision||"No decision"):summary.result_state==="coverage_incomplete"?"Partial coverage":"No findings";
  const cls=hasFindings?outcome.toLowerCase().replaceAll(" ","-"):"no-findings";
  const outcomeKey=OUTCOME_ORDER.find(([,label])=>label===outcome)?.[0]||"";
  const view=VIEWS.get(summary.target_id)||{tab:"overview",finding:0};
  const review=summary.ssvc_inputs_review_total||0;
  const tabs=[["overview","Overview",summary.total],["path","Decision path",""],["actions","Action queue",summary.actions],["evidence","Evidence & policy",""],["review","Review inputs",review]];
  const content=view.tab==="overview"?overviewBlock(summary):view.tab==="actions"?(queueBlock(summary)||'<div class="emptyresult"><b>No package actions</b><span>Review the evidence and coverage in the report.</span></div>'):view.tab==="evidence"?`<div class="microtitle">Highest-priority finding · ${esc(summary.explanation?.vuln_id||"No findings")}</div>${explainBlock(summary)}${qualityBlock(summary)}<details class="compare"><summary>Compare ranking methods</summary>${compareBlock(summary)}</details>`:view.tab==="review"?(ssvcInputBlock(summary)||'<div class="emptyresult"><b>No finding inputs to review</b></div>'):treeBlock(summary);
  const warnings=[...(summary.enrichment_errors||[]),...(summary.vendor_errors||[])];
  const context=summary.evaluated_context||{};
  return `<article class="result" style="--top:${OUTCOME_COLOR[outcomeKey]||"var(--line2)"}" data-result="${esc(summary.target_id)}" data-id="${esc(summary.target_id)}">
    <div class="resulthead">
      <div class="prioritybox"><div class="priority ${esc(cls)}" data-outcome="${outcomeKey}">${esc(outcome)}</div><div class="prioritymeaning" title="Highest-priority SSVC outcome">${hasFindings?"Top outcome":"Evidence coverage"}</div><div class="prioritydue">${summary.top_deadline_days==null?"":`workflow ≤ ${esc(summary.top_deadline_days)} days`}</div></div>
      <div><div class="rname">${esc(summary.name)} · ${summary.total} findings · ${summary.actions} actions${summary.demo?" · offline demo":""}</div><div class="action">${esc(summary.top_action||"Assessment completed")}</div><div class="resulttools"><button class="textbutton" data-action="edit">Review context</button><button class="textbutton" data-action="manage">Manage evidence</button><button class="textbutton" data-action="run">Run again</button></div></div>
      <div class="reportlinks"><a class="reportlink" href="${esc(summary.report_url)}" target="_blank" rel="noopener">Open full report →</a><a class="reportlink" href="${esc(summary.report_url)}" download="${esc(reportFilename(summary))}">Download HTML report</a></div>
    </div>
    ${(coverage!=="complete"||warnings.length)?`<details class="resultnotice"><summary>${coverage!=="complete"?`Coverage: ${esc(coverage.replaceAll("_"," "))}`:"Evidence lookup warnings"}${warnings.length?` · ${warnings.length} lookup warning(s)`:""} · View details</summary><p>${esc(summary.result_message||"Coverage is limited to the supplied evidence; zero findings does not prove safety.")}</p>${warnings.map(w=>`<p>${esc(w)}</p>`).join("")}</details>`:""}
    <div class="resulttabs" role="tablist" aria-label="Result details">${tabs.map(([key,label,count])=>`<button class="resulttab" role="tab" id="tab-${key}" data-tab="${key}" aria-selected="${view.tab===key}" aria-controls="result-panel" tabindex="${view.tab===key?0:-1}">${label}${count!==""?`<span class="tabcount ${key==="review"&&count?"warn":""}">${count}</span>`:""}</button>`).join("")}</div>
    <div class="resultpanel" id="result-panel" role="tabpanel" aria-labelledby="tab-${view.tab}" tabindex="0">${content}</div>
  </article>`;
}

function qualityBlock(summary){
  const q=summary.decision_quality;
  if(!q||!q.points_total)return "";
  const sources=Object.entries(q.sources||{}).map(([name,count])=>
    `<span class="metric ${name.startsWith("CISA")||name.startsWith("analyst")?"audit":""}">${esc(name)} ${count}</span>`).join("");
  const deEscalated=q.de_escalated
    ? `<span class="metric audit" title="A published CISA assessment was less urgent than the conservative default PatchTriage would otherwise apply. Without it these findings would have been over-prioritized.">${q.de_escalated} de-escalated by CISA assessment</span>`
    : "";
  return `<div class="metricrow">
    <span class="metric"><b>${q.authoritative}/${q.points_total}</b> decision inputs from authority (${q.authoritative_pct}%)</span>
    <span class="metric ${q.assumed?"alert":""}">${q.assumed} assumed by conservative default</span>
    <span class="metric ${q.needs_confirmation?"alert":""}">${q.needs_confirmation} finding(s) need confirmation</span>
    ${deEscalated}${sources}
  </div>`;
}
function targetName(id){const target=TARGETS.find(item=>item.id===id);return target?target.name:id;}
function statusCard(id,status){
  const active=["queued","running","reconnecting"].includes(status.state);
  const disconnected=status.state==="disconnected";
  const title=status.state==="queued"?`Waiting to assess ${targetName(id)}`:status.state==="reconnecting"?`Reconnecting to ${targetName(id)}…`:active?`Assessing ${targetName(id)}…`:disconnected?`Connection interrupted: ${targetName(id)}`:status.state==="interrupted"?`Run status unavailable: ${targetName(id)}`:`Assessment failed: ${targetName(id)}`;
  const message=status.state==="queued"?"This target will start when an assessment slot is available.":status.state==="reconnecting"?"The server may still be working. Retrying the connection; no new assessment is started.":active?"Checking evidence, evaluating SSVC and saving your report. You can select another target or refresh this page.":status.error||"The assessment did not finish.";
  return `<article class="result statecard ${active?"running":"failed"} lightpanel" data-status="${esc(id)}" ${active?'aria-busy="true"':'role="alert"'}><div><strong>${esc(title)}</strong><span>${esc(message)}</span>${active?'<div class="scanline"></div>':disconnected?'<span>Check the existing run before starting a new assessment.</span>':'<span>No decision is shown for this target until a run succeeds. Check the evidence and context, then retry.</span>'}</div>${active?"":`<button class="btn small ${disconnected?"reconnect-run":"retry-run"}" data-id="${esc(id)}">${disconnected?"Reconnect to assessment":"Retry assessment"}</button>`}</article>`;
}
function emptyWorkspace(){return `<div class="empty lightpanel"><div class="emptycontent"><div class="eyebrow">Evidence → decision → action</div><h3>What should you patch first?</h3><p>Add a system and its scan or SBOM. See the next action and the evidence behind every decision.</p><div class="startsteps"><div class="startstep"><b><span>01</span> Add a target</b>Name the system and its context.</div><div class="startstep"><b><span>02</span> Add evidence</b>Upload a scan or import a repository.</div><div class="startstep"><b><span>03</span> Run triage</b>Review the path. Save your report.</div></div><div class="startactions"><button class="btn primary new-target-trigger">+ Add your first target</button><button class="btn demo-trigger">Try the offline demo</button></div></div></div>`;}
function targetSetup(target){
  return `<article class="empty lightpanel" data-id="${esc(target.id)}"><div class="emptycontent"><div class="eyebrow">${target.source_file?"Ready to assess":"Step 2 · Add evidence"}</div><h3>${esc(target.name)}</h3><p>${target.source_file?"Your evidence is attached. Run triage to produce the decision path and a downloadable report.":"Upload CycloneDX/SPDX JSON (or Trivy/Grype/OSV scanner JSON), or import a repository."}</p><div class="targetsummary">${contextTags(target)}</div>${target.source_file?`<p class="source ready">${esc(target.source_name||target.source_format)} · ${Math.max(1,Math.round((target.source_size||0)/1024))} KiB · SHA-256 ${esc((target.source_sha256||"").slice(0,12))}</p>`:""}<div class="startactions">${target.source_file?'<button class="btn primary" data-action="run">Run triage →</button>':''}<button class="btn ${target.source_file?"":"primary"}" data-action="import">Upload SBOM</button><button class="btn attach" data-action="repository">Import repository</button></div><div class="targetactions"><button class="textbutton" data-action="edit">Review context</button><button class="textbutton" data-action="delete">Delete target</button>${RESULTS.has(target.id)?'<button class="textbutton" data-action="view">Back to results</button>':""}</div></div></article>`;
}
function renderResults(){
  const results=document.getElementById("results"),target=TARGETS.find(t=>t.id===selectedTarget);
  renderOutcomeSummary();
  const status=STATUS.get(selectedTarget),summary=RESULTS.get(selectedTarget);
  const key=JSON.stringify([selectedTarget,status,summary?.run_generation,summary?.assessed_at,target?.input_revision,VIEWS.get(selectedTarget)]);
  // A different target finishing must not erase unsaved analyst inputs or
  // keyboard focus in the currently visible result.
  if(key!==renderedView){results.innerHTML=!target?emptyWorkspace():status?statusCard(selectedTarget,status):summary&&!VIEWS.get(selectedTarget)?.manage?renderResult(summary):targetSetup(target);renderedView=key;}
  document.getElementById("workspace-step").textContent=target?`${target.name} · ${status?"Assessment status":summary?"Review the decision, then download the report":target.source_file?"3. Run triage":"2. Upload SBOM or import a repository"}`:"1. Add a target → 2. Add evidence → 3. Run triage";
  updateKpis();renderTargets();if(!booting)refreshFleet();setBusy();
}

async function refreshFleet(){
  const bar=document.getElementById("fleetbar");
  try{
    const fleet=await api("GET","/api/fleet/summary");
    if((fleet.targets_assessed||0)<2){bar.hidden=true;return;}
    const o=fleet.outcomes||{};
    const queue=(fleet.queue||[]).slice(0,3).map(entry=>`<div class="hint">&#8227; <b>${esc(entry.outcome_label||"")}</b> — ${esc(entry.target_name||"")}: ${esc(entry.summary||"")}${entry.kev_count?` <span style="color:var(--c-immediate);font-weight:700">KEV×${entry.kev_count}</span>`:""}</div>`).join("");
    bar.innerHTML=`<summary>Fleet view — ${fleet.targets_assessed}/${fleet.targets_total} targets assessed · ${fleet.findings_total} findings</summary>`+
      `<span style="color:var(--c-immediate);font-weight:700">${o.immediate||0} Immediate</span> · <span style="color:var(--c-outofcycle);font-weight:650">${o.out_of_cycle||0} Out-of-Cycle</span> · ${o.scheduled||0} Scheduled · ${o.defer||0} Defer · ${fleet.kev_total||0} on KEV`+
      `${fleet.coverage_incomplete_targets?` · <span style="color:var(--c-outofcycle)">${fleet.coverage_incomplete_targets} with bounded coverage</span>`:""}${queue?`<div style="margin-top:6px">${queue}</div>`:""}`;
    bar.hidden=false;
  }catch(error){bar.hidden=true;}
}
async function launchDemo(){
  const button=document.getElementById("demo");if(button.disabled)return;
  button.disabled=true;window.location.hash="workspace";showPage();
  try{notify("Loading bundled threat evidence…");const target=await api("POST","/api/demo",{});await loadTargets();selectTarget(target.id);const outcomes=await runTargets([target.id]);if(outcomes.every(Boolean))notify("Offline demo is ready. Select a CVE to open its decision path.");}
  catch(error){notify(error.message,true);}
  finally{button.disabled=false;}
}
const WATCHERS=new Map(),RUN_QUEUE=[],SUBMITTING=new Map();let queueRetryAt=0;
function saveQueue(){try{sessionStorage.setItem("patchtriage-queue",JSON.stringify([...RUN_QUEUE,...SUBMITTING.values()].map(({id,backend,queuedAt,revision})=>({id,backend,queuedAt,revision}))));}catch{}}
async function waitForJob(jobId,id){
  let failures=0;
  for(let attempt=0;attempt<1800;attempt++){
    try{
      const job=await api("GET",`/api/jobs/${jobId}`);
      failures=0;
      if(job.state==="succeeded"){
        if(!job.summary||job.summary.target_id!==id||!job.summary.report_url)throw new Error("The completed run has no valid report. Reconnect to check it.");
        return job.summary;
      }
      if(job.state==="failed"){const error=new Error(job.error||"Assessment failed");error.assessmentFailed=true;throw error;}
      if(!["queued","running"].includes(job.state)){const error=new Error("Unknown assessment state. Reconnect to check it.");error.retryable=true;throw error;}
      if(STATUS.get(id)?.state!==job.state){STATUS.set(id,{state:job.state,jobId});renderResults();}
    }catch(error){
      if(error.assessmentFailed)throw error;
      if(error.status===404){error.interrupted=true;error.message="The server no longer has this job, possibly after a restart. Retry assessment to generate a new report.";throw error;}
      if(!error.retryable||++failures>=5){error.disconnected=true;throw error;}
      STATUS.set(id,{state:"reconnecting",jobId});renderResults();
    }
    await new Promise(resolve=>setTimeout(resolve,failures?Math.min(8000,1000*2**failures):Math.min(2000,500+attempt*25)));
  }
  const error=new Error("This run is taking longer than expected. Reconnect to check its status.");error.disconnected=true;throw error;
}
function watchJob(id,jobId){
  if(WATCHERS.has(id))return WATCHERS.get(id);
  STATUS.set(id,{state:"running",jobId});
  const promise=waitForJob(jobId,id).then(summary=>{STATUS.delete(id);RESULTS.set(id,summary);return true;},error=>{STATUS.set(id,{state:error.interrupted?"interrupted":error.disconnected?"disconnected":"failed",jobId,error:error.message});return false;}).finally(()=>{WATCHERS.delete(id);renderResults();pumpQueue();});
  WATCHERS.set(id,promise);return promise;
}
async function reconnectTarget(id){
  const jobId=STATUS.get(id)?.jobId;
  if(jobId){const pending=watchJob(id,jobId);renderResults();return pending;}
  try{
    const jobs=await api("GET","/api/jobs?latest=1"),job=jobs.find(j=>j.target_id===id);
    if(job){const pending=watchJob(id,job.job_id);renderResults();return pending;}
    STATUS.set(id,{state:"interrupted",error:"No assessment job could be recovered. Retry assessment to generate a report."});
  }catch(error){STATUS.set(id,{state:"disconnected",error:error.message});}
  renderResults();return false;
}
function enqueue(id,backend,queuedAt=Date.now()/1000){
  if(WATCHERS.has(id))return WATCHERS.get(id);
  if(SUBMITTING.has(id))return SUBMITTING.get(id).promise;
  const existing=RUN_QUEUE.find(item=>item.id===id);if(existing)return existing.promise;
  let finish;const promise=new Promise(resolve=>finish=resolve);
  const revision=TARGETS.find(t=>t.id===id)?.input_revision;
  RUN_QUEUE.push({id,backend,queuedAt,revision,promise,finish});RESULTS.delete(id);STATUS.set(id,{state:"queued"});saveQueue();return promise;
}
function pumpQueue(){
  if(booting||Date.now()<queueRetryAt)return;
  const capacity=Math.max(1,Math.min(2,CFG.limits?.active_jobs_per_session||2));
  while(RUN_QUEUE.length&&WATCHERS.size+SUBMITTING.size<capacity){
    const item=RUN_QUEUE.shift();SUBMITTING.set(item.id,item);saveQueue();
    (async()=>{
      try{
        const id=item.id,job=await api("POST",`/api/targets/${id}/runs`,{backend:item.backend});
        const pending=watchJob(id,job.job_id);SUBMITTING.delete(id);saveQueue();pumpQueue();item.finish(await pending);
      }catch(error){
        // A lost POST response may still have started a run. Check the
        // session's jobs before presenting a retry or starting another one.
        try{
          const jobs=await api("GET","/api/jobs?latest=1");const job=jobs.find(j=>j.target_id===item.id&&j.created_at>=item.queuedAt);
          if(job){const pending=watchJob(item.id,job.job_id);SUBMITTING.delete(item.id);saveQueue();item.finish(await pending);return;}
          if(error.status===429){SUBMITTING.delete(item.id);RUN_QUEUE.unshift(item);saveQueue();queueRetryAt=Date.now()+2000;setTimeout(pumpQueue,2000);return;}
        }catch{}
        SUBMITTING.delete(item.id);saveQueue();
        STATUS.set(item.id,{state:error.retryable?"disconnected":"failed",error:error.message});item.finish(false);
      }finally{renderResults();pumpQueue();}
    })();
  }
}
async function runTargets(ids){
  ids=ids.filter(id=>TARGETS.find(t=>t.id===id)?.source_file);
  if(!ids.length){notify("Upload an SBOM or import a repository first.",true);return [];}
  const backend=document.getElementById("backend").value||CFG.backends[0]||"rules";
  const pending=ids.map(id=>{const view=VIEWS.get(id)||{tab:"overview",finding:0};view.manage=false;VIEWS.set(id,view);return enqueue(id,backend);});
  renderResults();pumpQueue();const settled=await Promise.all(pending);
  const failed=settled.filter(ok=>!ok).length;if(failed)notify(`${failed} assessment(s) need attention. Select the target for details.`,true);
  return settled;
}
document.getElementById("demo").onclick=launchDemo;
document.getElementById("new-target").onclick=openTargetForm;
document.getElementById("context-close").onclick=()=>document.getElementById("contextdialog").close();
document.getElementById("landing-demo").onclick=launchDemo;
function showPage(focus=false){
  const workspace=window.location.hash==="#workspace";
  document.getElementById("home").hidden=workspace;
  document.getElementById("workspace").hidden=!workspace;
  document.getElementById("home-link").hidden=!workspace;
  document.getElementById("workspace-link").hidden=workspace;
  if(focus)document.getElementById(workspace?"workspace-title":"home-title").focus({preventScroll:true});
}
window.addEventListener("hashchange",()=>showPage(true));
showPage();

async function saveSsvcInputs(card){
  const id=card.dataset.result;
  const inputs=[...card.querySelectorAll(".ssvcinputtable tbody tr")].map(row=>{const exploitation=row.querySelector('[data-field="exploitation"]').value,automatable=row.querySelector('[data-field="automatable"]').value;return {finding_key:row.dataset.key,exploitation,automatable,changed:exploitation!==row.dataset.exploitation||automatable!==row.dataset.automatable};}).filter(item=>item.changed).map(({changed,...item})=>item);
  if(!inputs.length){notify("No SSVC input changes to save.");return;}
  try{setBusy(true);await api("POST",`/api/targets/${id}/ssvc-inputs`,{inputs});notify("SSVC inputs saved. Re-running the decision…");await runTargets([id]);}
  catch(error){notify(error.message,true);setBusy(false);}
}
document.getElementById("results").addEventListener("change",event=>{
  const select=event.target.closest(".treeselect");if(!select)return;
  const card=select.closest(".result"),summary=RESULTS.get(card.dataset.result),path=((summary||{}).decision_paths||[])[Number(select.value)];
  if(path){const view=VIEWS.get(card.dataset.result)||{tab:"path"};view.finding=Number(select.value);VIEWS.set(card.dataset.result,view);renderResults();}
});
document.getElementById("results").onclick=event=>{
  if(event.target.closest(".demo-trigger"))launchDemo();
  if(event.target.closest(".new-target-trigger"))openTargetForm();
  const tab=event.target.closest("[data-tab]");if(tab){const view=VIEWS.get(selectedTarget)||{finding:0};view.tab=tab.dataset.tab;VIEWS.set(selectedTarget,view);renderResults();document.getElementById("tab-"+view.tab).focus();}
  const flow=event.target.closest("[data-flow]");if(flow)toggleFlowFilter(flow);
  if(event.target.closest(".clearflow")){const view=VIEWS.get(selectedTarget);if(view){view.filter={};renderResults();document.getElementById("tab-overview")?.focus();}}
  const open=event.target.closest(".openpath");if(open){const view=VIEWS.get(selectedTarget)||{};view.tab="path";view.finding=Number(open.dataset.path);VIEWS.set(selectedTarget,view);renderResults();document.getElementById("tab-path").focus();}
  const action=event.target.closest("[data-action]");if(action)handleTargetAction(action);
  const reconnect=event.target.closest(".reconnect-run");if(reconnect)reconnectTarget(reconnect.dataset.id);
  const retry=event.target.closest(".retry-run");if(retry)runTargets([retry.dataset.id]);
  const save=event.target.closest(".save-ssvc-inputs");if(save)saveSsvcInputs(save.closest(".result"));
};
function toggleFlowFilter(el){
  const id=el.closest(".result")?.dataset.result;if(!id)return;
  const view=VIEWS.get(id)||{tab:"overview",finding:0},next=JSON.parse(el.dataset.flow),current=view.filter||{};
  // Selecting the active filter again clears it.
  const same=Object.keys(next).length===Object.keys(current).length&&Object.entries(next).every(([k,v])=>current[k]===v);
  view.filter=same?{}:next;VIEWS.set(id,view);renderResults();
  // The chart was redrawn; keep keyboard focus on the same box or ribbon.
  [...document.querySelectorAll('[data-flow][tabindex="0"]')].find(n=>n.dataset.flow===el.dataset.flow)?.focus({preventScroll:true});
}
document.getElementById("results").addEventListener("keydown",event=>{
  if(event.target.matches("[data-flow]")&&(event.key==="Enter"||event.key===" ")){event.preventDefault();toggleFlowFilter(event.target);return;}
  if(!event.target.matches('[role="tab"]'))return;
  const tabs=[...event.target.parentElement.querySelectorAll('[role="tab"]')],index=tabs.indexOf(event.target);
  const next=event.key==="ArrowRight"?(index+1)%tabs.length:event.key==="ArrowLeft"?(index+tabs.length-1)%tabs.length:event.key==="Home"?0:event.key==="End"?tabs.length-1:null;
  if(next!==null){event.preventDefault();tabs[next].click();}
});
const SSVC_FIELDS=[
  {key:"exposure",select:"f-exposure",fallback:"open",
   values:{
     open:"Reachable from the internet, or from a network so broad that access cannot plausibly be restricted.",
     controlled:"Networked, but access controls in front of it reliably interrupt an attack — a VPN, an allow-list, an authenticating proxy.",
     small:"Local-only or highly controlled: a handful of accounts on a segmented network can reach it."}},
  {key:"mission",select:"f-mission",fallback:"mef_support_crippled",
   values:{
     degraded:"Little to no mission impact. What degrades is not essential work.",
     mef_support_crippled:"Activities that support an essential function are crippled, but the essential function itself keeps running for now.",
     mef_failure:"One mission essential function fails, for longer than the organization can tolerate.",
     mission_failure:"Several or all mission essential functions fail — the organization cannot deliver its mission."}},
  {key:"safety",select:"f-safety",fallback:"marginal",
   values:{
     negligible:"Minor injury at worst, or a small reduction in a safety margin that operators absorb without extra effort.",
     marginal:"Major injury, or a safety-critical capability fails and operators must actively work around it.",
     critical:"Loss of a life is credible, or the system takes serious but recoverable damage.",
     catastrophic:"Multiple deaths, or total loss of the system or its environment."}}];
const SSVC_FALLBACK_NOTE={
  exposure:"SSVC treats unknown exposure as the most dangerous case.",
  mission:"SSVC treats unknown mission impact as support for essential work already being crippled.",
  safety:"SSVC treats unknown safety impact as a major-injury case."};
function ssvcLabel(id){const select=document.getElementById(id),option=select.options[select.selectedIndex];return option?option.textContent:"";}
function syncSsvcContext(){
  let answered=0;
  for(const field of SSVC_FIELDS){
    const select=document.getElementById(field.select),wrap=document.getElementById("fw-"+field.key),
          note=document.getElementById("d-"+field.key),value=select.value,assessed=value!=="unknown";
    if(assessed)answered++;
    wrap.classList.toggle("set",assessed);wrap.classList.toggle("pending",!assessed);
    note.classList.toggle("fallback",!assessed);
    note.innerHTML=assessed
      ?"<b>"+esc(ssvcLabel(field.select))+".</b> "+esc(field.values[value]||"")
      :"<b>Falls back to "+esc(SSVC_LABELS[field.fallback]||field.fallback)+".</b> "
        +" Confirm when known.";
  }
  const progress=document.getElementById("ssvc-progress");
  progress.textContent=answered+" of 3 answered";
  progress.classList.toggle("done",answered===3);
  const mission=document.getElementById("f-mission").value,safety=document.getElementById("f-safety").value,
        effectiveMission=mission==="unknown"?"mef_support_crippled":mission,
        effectiveSafety=safety==="unknown"?"marginal":safety,
        human=HUMAN_IMPACT[effectiveSafety+"|"+effectiveMission],
        assumed=mission==="unknown"||safety==="unknown";
  document.getElementById("d-human").textContent=SSVC_LABELS[human]||"—";
  document.getElementById("d-humanpath").textContent=
    SSVC_LABELS[effectiveMission]+" mission + "+SSVC_LABELS[effectiveSafety]+" safety"
    +(assumed?" (partly assumed)":"");
}
SSVC_FIELDS.forEach(field=>document.getElementById(field.select).addEventListener("change",syncSsvcContext));
function optionalBool(id){const value=document.getElementById(id).value;return value==="unknown"?null:value==="true";}
function contextPayload(){return {system_exposure:document.getElementById("f-exposure").value,mission_impact:document.getElementById("f-mission").value,safety_impact:document.getElementById("f-safety").value,criticality:document.getElementById("f-criticality").value,internet_exposed:optionalBool("f-internet"),reachable:optionalBool("f-reachable"),runtime_observed:optionalBool("f-runtime"),context_sources:document.getElementById("f-sources").value.split(",").map(value=>value.trim()).filter(Boolean),bod2604_applicability:document.getElementById("f-bod").value,publicly_exposed:document.getElementById("f-public").value};}
function resetForm(){editingTarget=null;document.getElementById("form-title").textContent="Add a target";document.getElementById("add").textContent="Add target";document.getElementById("cancel-edit").hidden=true;["f-name","f-url","f-sources"].forEach(id=>{document.getElementById(id).disabled=false;document.getElementById(id).value="";});["f-exposure","f-mission","f-safety","f-criticality","f-internet","f-reachable","f-runtime","f-bod","f-public"].forEach(id=>document.getElementById(id).value="unknown");syncSsvcContext();}
function boolChoice(value){return value===true?"true":value===false?"false":"unknown";}
function editContext(target){editingTarget=target.id;document.getElementById("form-title").textContent="Review SSVC context";document.getElementById("add").textContent="Save context";document.getElementById("cancel-edit").hidden=false;document.getElementById("f-name").value=target.name;document.getElementById("f-url").value=target.url||"";["f-name","f-url"].forEach(id=>document.getElementById(id).disabled=true);document.getElementById("f-exposure").value=target.system_exposure||"unknown";document.getElementById("f-mission").value=target.mission_impact||"unknown";document.getElementById("f-safety").value=target.safety_impact||"unknown";document.getElementById("f-criticality").value=target.criticality||"unknown";document.getElementById("f-internet").value=boolChoice(target.internet_exposed);document.getElementById("f-reachable").value=boolChoice(target.reachable);document.getElementById("f-runtime").value=boolChoice(target.runtime_observed);document.getElementById("f-sources").value=(target.context_sources||[]).join(", ");document.getElementById("f-bod").value=target.bod2604_applicability||"unknown";document.getElementById("f-public").value=target.publicly_exposed||"unknown";document.getElementById("bodform").open=["f-bod","f-public","f-criticality","f-internet","f-reachable","f-runtime"].some(id=>document.getElementById(id).value!=="unknown")||!!document.getElementById("f-sources").value;syncSsvcContext();document.getElementById("contextdialog").showModal();document.getElementById("f-exposure").focus();}
document.getElementById("add").onclick=async()=>{
  const name=document.getElementById("f-name").value.trim();if(!editingTarget&&!name){notify("Give the target a system name.",true);return;}
  const save=document.getElementById("add");if(save.disabled)return;save.disabled=true;
  try{
    const wasEditing=editingTarget;let created=null;if(editingTarget){await api("POST",`/api/targets/${editingTarget}/context`,contextPayload());RESULTS.delete(editingTarget);STATUS.delete(editingTarget);}else{created=await api("POST","/api/targets",{name,url:document.getElementById("f-url").value.trim(),...contextPayload()});}
    resetForm();document.getElementById("contextdialog").close();await loadTargets();if(created)selectedTarget=created.id;rememberSelection();renderResults();
    if(created){const card=document.querySelector(`.target[data-id="${created.id}"]`);if(card){card.scrollIntoView({behavior:"smooth",block:"center"});const next=card.querySelector('[data-action="import"]');if(next)next.focus({preventScroll:true});}}
    notify(wasEditing?"SSVC context saved. Run the target again to apply it.":"Target added. Next: upload its SBOM, or import a repository.");
  }catch(error){notify(error.message,true);}
  finally{save.disabled=false;}
};
document.getElementById("cancel-edit").onclick=()=>{resetForm();document.getElementById("contextdialog").close();};
async function handleTargetAction(button){
  const card=button.closest("[data-id]"),id=card.dataset.id,action=button.dataset.action;
  if(action==="select"){selectTarget(id);return;}
  if(action==="manage"||action==="view"){const view=VIEWS.get(id)||{tab:"overview",finding:0};view.manage=action==="manage";VIEWS.set(id,view);renderResults();return;}
  if(isPending(id)&&["edit","import","repository","delete"].includes(action)){notify("Wait for this assessment to finish before changing its inputs.",true);return;}
  if(action==="edit")editContext(TARGETS.find(target=>target.id===id));
  if(action==="import"){pickTarget=id;document.getElementById("filepick").click();}
  if(action==="repository"){repoTarget=id;document.getElementById("repo-url").value="";document.getElementById("repodialog").showModal();document.getElementById("repo-url").focus();}
  if(action==="run")runTargets([id]);
  if(action==="delete"&&confirm("Delete this target and its local evidence?")){
    try{await api("DELETE","/api/targets/"+id);RESULTS.delete(id);STATUS.delete(id);await loadTargets();renderResults();notify("Target deleted.");}
    catch(error){notify(error.message,true);}
  }
}
document.getElementById("targetlist").onclick=event=>{const button=event.target.closest("[data-action]");if(button)handleTargetAction(button);};
document.getElementById("fleet-open").onclick=()=>{document.getElementById("fleet-url").value="";document.getElementById("fleetdialog").showModal();document.getElementById("fleet-url").focus();};
document.getElementById("fleet-cancel").onclick=()=>document.getElementById("fleetdialog").close();
document.getElementById("fleet-import").onclick=async()=>{
  const ownerUrl=document.getElementById("fleet-url").value.trim();
  if(!ownerUrl){notify("Enter a GitHub organization or user URL.",true);return;}
  const limit=parseInt(document.getElementById("fleet-limit").value,10)||10;
  try{
    document.getElementById("fleet-import").disabled=true;notify("Listing repositories and fetching SBOMs…");
    const report=await api("POST","/api/fleet/import",{owner_url:ownerUrl,limit});
    document.getElementById("fleetdialog").close();await loadTargets();renderResults();
    const failed=report.failed?`, ${report.failed} failed`:"";
    const existing=report.already_imported?`, ${report.already_imported} already imported`:"";
    notify(`Imported ${report.imported} repositories from ${report.owner}${existing}${failed}. Press "Run all" to assess the fleet.`,Boolean(report.stopped_reason));
    if(report.stopped_reason)notify(report.stopped_reason,true);
  }catch(error){notify("Organization import failed: "+error.message,true);}
  finally{document.getElementById("fleet-import").disabled=false;}
};
document.getElementById("repo-cancel").onclick=()=>{repoTarget=null;document.getElementById("repodialog").close();};
document.getElementById("repo-import").onclick=async()=>{
  const repositoryUrl=document.getElementById("repo-url").value.trim();
  if(!repoTarget||!repositoryUrl){notify("Enter a GitHub repository URL.",true);return;}
  const targetId=repoTarget;
  try{
    document.getElementById("repo-import").disabled=true;notify("Fetching GitHub Dependency Graph SBOM...");
    const imported=await api("POST",`/api/targets/${targetId}/repository`,{repository_url:repositoryUrl});
    RESULTS.delete(targetId);STATUS.delete(targetId);document.getElementById("repodialog").close();repoTarget=null;await loadTargets();renderResults();
    notify(`${imported.filename} imported (${imported.provenance.component_count} components).`);
  }catch(error){notify("Repository import failed: "+error.message,true);}
  finally{document.getElementById("repo-import").disabled=false;}
};
document.getElementById("filepick").onchange=async event=>{
  const file=event.target.files[0];if(!file||!pickTarget)return;
  const maxBytes=(CFG.limits&&CFG.limits.source_bytes)||16*1024*1024;
  if(file.size>maxBytes){notify(`Evidence file must be ${Math.floor(maxBytes/1024/1024)} MiB or smaller.`,true);event.target.value="";return;}
  try{const targetId=pickTarget;const imported=await api("POST",`/api/targets/${targetId}/source`,{content:await file.text(),filename:file.name});RESULTS.delete(targetId);STATUS.delete(targetId);await loadTargets();renderResults();notify(`${file.name} attached (SHA-256 ${imported.sha256.slice(0,12)}).`);}
  catch(error){notify("Import failed: "+error.message,true);}
  event.target.value="";pickTarget=null;
};
document.getElementById("runall").onclick=()=>runTargets(TARGETS.filter(t=>t.source_file).map(t=>t.id));

function showBootError(error){booting=false;renderedView="";document.getElementById("results").innerHTML=`<div class="result statecard failed" role="alert"><strong>Workspace could not be loaded</strong><span>${esc(error.message)}</span><button class="btn" id="retry-boot">Reconnect to workspace</button></div>`;document.getElementById("retry-boot").onclick=()=>boot().catch(showBootError);}
async function boot(){
  booting=true;syncSsvcContext();
  // Establish the anonymous cookie before making parallel session requests.
  await loadConfig();await loadTargets();await resumeActiveJobs();
  booting=false;renderResults();pumpQueue();
}
try{selectedTarget=sessionStorage.getItem("patchtriage-selection");}catch{}
boot().catch(showBootError);
</script></body></html>"""


INDEX_HTML = (
    _TEMPLATE
    .replace("__SSVC_LABELS__", json.dumps(_decision_point_labels()))
    .replace("__HUMAN_IMPACT__", json.dumps(_human_impact_matrix()))
)
