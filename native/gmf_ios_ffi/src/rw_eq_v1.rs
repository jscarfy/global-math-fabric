use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag="t")]
pub enum Expr {
    #[serde(rename="c")] C { v: i64 },
    #[serde(rename="v")] V { n: String },
    #[serde(rename="+")] Add { a: Vec<Expr> },
    #[serde(rename="*")] Mul { a: Vec<Expr> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub rule: String,
    pub path: Vec<u32>, // indices into a[]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub steps: u32,
    pub nodes0: u32,
    pub nodesf: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag="kind")]
pub enum Output {
    #[serde(rename="rw_eq_v1_result")]
    Ok { ok: bool, final_: Expr, steps: Vec<Step>, stats: Stats },

    #[serde(rename="gmf_error")]
    Err { message: String },
}

fn nodes(e: &Expr) -> u32 {
    match e {
        Expr::C{..} | Expr::V{..} => 1,
        Expr::Add{a} | Expr::Mul{a} => 1 + a.iter().map(nodes).sum::<u32>(),
    }
}

fn canon_key(e: &Expr) -> String {
    // stable canonical key (not too slow)
    match e {
        Expr::C{v} => format!("c:{v}"),
        Expr::V{n} => format!("v:{n}"),
        Expr::Add{a} => {
            let mut ks: Vec<String> = a.iter().map(canon_key).collect();
            ks.sort();
            format!("+({})", ks.join(","))
        }
        Expr::Mul{a} => {
            let mut ks: Vec<String> = a.iter().map(canon_key).collect();
            ks.sort();
            format!("*({})", ks.join(","))
        }
    }
}

fn get_mut_at<'a>(e: &'a mut Expr, path: &[u32]) -> Option<&'a mut Expr> {
    if path.is_empty() { return Some(e); }
    let (h, t) = (path[0] as usize, &path[1..]);
    match e {
        Expr::Add{a} | Expr::Mul{a} => {
            if h >= a.len() { return None; }
            get_mut_at(&mut a[h], t)
        }
        _ => None,
    }
}

fn rule_add_flatten(e: &mut Expr) -> bool {
    match e {
        Expr::Add{a} => {
            let mut out: Vec<Expr> = Vec::new();
            let mut changed = false;
            for x in a.drain(..) {
                if let Expr::Add{a:inner} = x {
                    out.extend(inner);
                    changed = true;
                } else {
                    out.push(x);
                }
            }
            *a = out;
            changed
        }
        _ => false
    }
}
fn rule_mul_flatten(e: &mut Expr) -> bool {
    match e {
        Expr::Mul{a} => {
            let mut out: Vec<Expr> = Vec::new();
            let mut changed = false;
            for x in a.drain(..) {
                if let Expr::Mul{a:inner} = x {
                    out.extend(inner);
                    changed = true;
                } else {
                    out.push(x);
                }
            }
            *a = out;
            changed
        }
        _ => false
    }
}
fn rule_add_sort(e: &mut Expr) -> bool {
    match e {
        Expr::Add{a} => {
            let before = a.iter().map(canon_key).collect::<Vec<_>>();
            a.sort_by(|x,y| canon_key(x).cmp(&canon_key(y)));
            let after = a.iter().map(canon_key).collect::<Vec<_>>();
            before != after
        }
        _ => false
    }
}
fn rule_mul_sort(e: &mut Expr) -> bool {
    match e {
        Expr::Mul{a} => {
            let before = a.iter().map(canon_key).collect::<Vec<_>>();
            a.sort_by(|x,y| canon_key(x).cmp(&canon_key(y)));
            let after = a.iter().map(canon_key).collect::<Vec<_>>();
            before != after
        }
        _ => false
    }
}
fn rule_add_drop0(e: &mut Expr) -> bool {
    match e {
        Expr::Add{a} => {
            let before = a.len();
            a.retain(|x| !matches!(x, Expr::C{v} if *v==0));
            if a.is_empty() { *e = Expr::C{v:0}; return true; }
            if a.len()==1 { *e = a[0].clone(); return true; }
            a.len()!=before
        }
        _ => false
    }
}
fn rule_mul_drop1(e: &mut Expr) -> bool {
    match e {
        Expr::Mul{a} => {
            let before = a.len();
            a.retain(|x| !matches!(x, Expr::C{v} if *v==1));
            if a.is_empty() { *e = Expr::C{v:1}; return true; }
            if a.len()==1 { *e = a[0].clone(); return true; }
            a.len()!=before
        }
        _ => false
    }
}
fn rule_mul_annihilate0(e: &mut Expr) -> bool {
    match e {
        Expr::Mul{a} => {
            if a.iter().any(|x| matches!(x, Expr::C{v} if *v==0)) {
                *e = Expr::C{v:0};
                true
            } else { false }
        }
        _ => false
    }
}
fn rule_add_foldconst(e: &mut Expr) -> bool {
    match e {
        Expr::Add{a} => {
            let mut sum: i64 = 0;
            let mut out: Vec<Expr> = Vec::new();
            let mut seen = false;
            for x in a.drain(..) {
                if let Expr::C{v} = x { sum += v; seen = true; }
                else { out.push(x); }
            }
            if seen { out.push(Expr::C{v:sum}); }
            *a = out;
            seen
        }
        _ => false
    }
}
fn rule_mul_foldconst(e: &mut Expr) -> bool {
    match e {
        Expr::Mul{a} => {
            let mut prod: i64 = 1;
            let mut out: Vec<Expr> = Vec::new();
            let mut seen = false;
            for x in a.drain(..) {
                if let Expr::C{v} = x { prod = prod.saturating_mul(v); seen = true; }
                else { out.push(x); }
            }
            if seen { out.push(Expr::C{v:prod}); }
            *a = out;
            seen
        }
        _ => false
    }
}

fn rule_distribute_left(e: &mut Expr) -> bool {
    // (* A (+ B C ...)) -> (+ (* A B) (* A C) ...)
    match e {
        Expr::Mul{a} if a.len()==2 => {
            let left = a[0].clone();
            let right = a[1].clone();
            if let Expr::Add{a:terms} = right {
                let expanded = terms.into_iter().map(|t| Expr::Mul{a: vec![left.clone(), t]}).collect();
                *e = Expr::Add{a: expanded};
                return true;
            }
            false
        }
        _ => false
    }
}
fn rule_distribute_right(e: &mut Expr) -> bool {
    // (* (+ B C ...) A) -> (+ (* B A) (* C A) ...)
    match e {
        Expr::Mul{a} if a.len()==2 => {
            let left = a[0].clone();
            let right = a[1].clone();
            if let Expr::Add{a:terms} = left {
                let expanded = terms.into_iter().map(|t| Expr::Mul{a: vec![t, right.clone()]}).collect();
                *e = Expr::Add{a: expanded};
                return true;
            }
            false
        }
        _ => false
    }
}

fn apply_rule_at(e: &mut Expr, rule: &str) -> bool {
    match rule {
        "add_flatten" => rule_add_flatten(e),
        "mul_flatten" => rule_mul_flatten(e),
        "add_sort" => rule_add_sort(e),
        "mul_sort" => rule_mul_sort(e),
        "add_drop0" => rule_add_drop0(e),
        "mul_drop1" => rule_mul_drop1(e),
        "mul_annihilate0" => rule_mul_annihilate0(e),
        "add_foldconst" => rule_add_foldconst(e),
        "mul_foldconst" => rule_mul_foldconst(e),
        "distribute_left" => rule_distribute_left(e),
        "distribute_right" => rule_distribute_right(e),
        _ => false
    }
}

fn normalize_one_pass(e: &mut Expr, steps: &mut Vec<Step>, path: &mut Vec<u32>, max_nodes: u32) -> bool {
    // recurse first (post-order)
    match e {
        Expr::Add{a} | Expr::Mul{a} => {
            for i in 0..a.len() {
                path.push(i as u32);
                let changed = normalize_one_pass(&mut a[i], steps, path, max_nodes);
                path.pop();
                if changed { return true; }
                if nodes(e) > max_nodes { return false; }
            }
        }
        _ => {}
    }

    // try local rules in fixed order
    let rules = [
        "add_flatten","mul_flatten",
        "mul_annihilate0",
        "add_foldconst","mul_foldconst",
        "add_drop0","mul_drop1",
        "distribute_left","distribute_right",
        "add_sort","mul_sort",
    ];
    for r in rules.iter() {
        let before = e.clone();
        if apply_rule_at(e, r) {
            steps.push(Step{ rule: r.to_string(), path: path.clone() });
            if nodes(e) > max_nodes {
                // revert if it explodes past bound
                *e = before;
                // remove step
                steps.pop();
                return false;
            }
            return true;
        }
    }
    false
}

pub fn solve_rw_eq_v1(start: Expr, goal: Expr, max_steps: u32, max_nodes: u32) -> Output {
    let nodes0 = nodes(&start);
    if nodes0 > max_nodes {
        return Output::Err{ message: "start exceeds max_nodes".into() };
    }

    let mut cur = start.clone();
    let mut steps: Vec<Step> = Vec::new();

    // deterministic normalize towards goal; we just normalize start until it equals goal or stuck or max_steps
    for _ in 0..max_steps {
        if cur == goal { break; }
        let mut path: Vec<u32> = Vec::new();
        let changed = normalize_one_pass(&mut cur, &mut steps, &mut path, max_nodes);
        if !changed { break; }
    }

    let ok = cur == goal;
    let stats = Stats{ steps: steps.len() as u32, nodes0, nodesf: nodes(&cur) };
    Output::Ok{ ok, final_: cur, steps, stats }
}

pub fn replay_rw_eq_v1(start: Expr, goal: Expr, steps: &[Step], max_steps: u32, max_nodes: u32) -> Result<(), String> {
    if steps.len() as u32 > max_steps { return Err("too many steps".into()); }
    let mut cur = start;
    for st in steps.iter() {
        let sub = get_mut_at(&mut cur, &st.path).ok_or("bad path")?;
        let before = sub.clone();
        let changed = apply_rule_at(sub, st.rule.as_str());
        if !changed { return Err("rule not applicable at path".into()); }
        if nodes(&cur) > max_nodes {
            // revert for deterministic behavior
            *sub = before;
            return Err("max_nodes exceeded".into());
        }
    }
    if cur != goal { return Err("final != goal".into()); }
    Ok(())
}
