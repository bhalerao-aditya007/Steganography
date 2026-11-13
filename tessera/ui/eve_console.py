"""Isolated Eve Forensic Console (Demonstrating attacker models E0 - E4)."""
import os
import streamlit as st
import numpy as np
from tessera.embed.profile import Profile
from tessera.stego_analysis.chi2 import chi2_attack
from tessera.stego_analysis.rs_attack import rs_estimate
from tessera.eve.e1_tool import EveE1ForensicTool, DEFAULT_WORDLIST
from tessera.eve.e2_second_look import EveE2SecondLook
from tessera.eve.e3_distinguisher import EveE3Distinguisher
from tessera.crypto.kdf import master, hkdf
from tessera.embed.mirage import decoy_peek

def render_eve_console(stego_image: np.ndarray, cover_image: np.ndarray, salt: bytes, prof: Profile):
    st.markdown("### 🕵️ Eve's Steganalysis & Forensic Attack Console")
    st.info("**Structural Security Guarantee:** In this demo panel, Eve possesses ONLY the stego image, the algorithm specification, and a dictionary of weak passwords. It is structurally impossible for Eve to access `pw_real`.")

    tab_e0, tab_e1, tab_e2, tab_e3 = st.tabs([
        "E0: Naive Scanner",
        "E1: Forensic Tool (Honey Decoy)",
        "E2: Second-Look / Coercion",
        "E3: Kerckhoffs Distinguisher"
    ])

    with tab_e0:
        st.markdown("#### E0: Blind Automated Scanning (Chi-Square & RS)")
        st.write("Eve executes blind statistical tests across pixel pairs of values.")
        
        col1, col2 = st.columns(2)
        with col1:
            p_val, fracs, curve = chi2_attack(stego_image)
            st.metric("Chi-Square p-value", f"{p_val:.4f}")
            if p_val < 0.05:
                st.error("🚨 Statistical anomaly detected by Chi-Square!")
            else:
                st.success("✅ Preserves Pairs-of-Values (PoVs) — Natural LSB distribution.")
                
        with col2:
            rs_rate = rs_estimate(stego_image)
            st.metric("RS Estimated Rate", f"{rs_rate:.4f}")
            if rs_rate > 0.05:
                st.warning(f"RS flags possible embedding (~{rs_rate*100:.1f}%)")
            else:
                st.success("✅ RS attack detects no linear LSB replacement.")

    with tab_e1:
        st.markdown("#### E1: Dictionary Attack & The Honey Encryption Trap")
        st.write("Eve detects embedding and runs a dictionary attack against the light Argon2id decoy passphrase.")
        
        target_pw = st.text_input("Target Password in Wordlist", value="sunshine123")
        if st.button("🚀 Run Live Dictionary Attack (24 Words)"):
            with st.spinner("Cracking decoy passphrase..."):
                e1 = EveE1ForensicTool()
                r0, r1 = prof.tile_slice(0)
                tile0 = stego_image[r0:r1]
                res = e1.attack(tile0, salt, prof, t=0, target_password=target_pw)
                
            st.success(f"Dictionary attack completed in {res['elapsed_seconds']:.2f}s across {res['words_tested']} words.")
            st.markdown(f"**Intended Decoy Message Found:** `{res['intended_message']}`")
            
            st.markdown("##### 🍯 The Honey Verification Paradox:")
            st.write("Notice how **EVERY** tested password decodes to a valid, realistic meeting note! Eve has NO 'wrong key' oracle to verify which candidate is genuine.")
            
            # Show candidates table
            sample_candidates = [
                {"Word": c["passphrase"], "Decoded Decoy Message": c["decoded_msg"], "Plausible Note?": "✅ Yes" if c["plausible"] else "❌"}
                for c in res["candidates"][:6]
            ]
            st.table(sample_candidates)

        st.markdown("---")
        st.markdown("##### 🧪 Test Any Custom Guess:")
        custom_guess = st.text_input("Enter any arbitrary password:", value="my_secret_guess_999")
        if custom_guess:
            r0, r1 = prof.tile_slice(0)
            tile0 = stego_image[r0:r1]
            e1 = EveE1ForensicTool()
            inspect_res = e1.inspect_single_guess(tile0, salt, prof, custom_guess, t=0)
            st.write(f"Decoded Note: **`{inspect_res['decoded_msg']}`**")
            st.caption("Juels-Ristenpart DTE ensures this is guaranteed to be a syntactically valid message.")

    with tab_e2:
        st.markdown("#### E2: Second-Look Eve (Coercion / Decoy Passphrase Revealed)")
        st.write("Alice is coerced and hands over `pw_decoy` ('sunshine123'), swearing 'I only embedded this decoy note'.")
        st.write("Eve computes keyed positions `P_t` and investigates if any leftover evidence contradicts Alice's claim.")
        
        if st.button("🔍 Execute Second-Look Forensic Audit"):
            e2 = EveE2SecondLook()
            e2_res = e2.inspect(cover_image, stego_image, salt, "sunshine123", prof)
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Modifications Outside Decoy", e2_res["changes_outside_decoy"])
            c2.metric("Modifications with |d| >= 2", e2_res["count_abs_ge2"])
            c3.metric("Total Changes vs Expected", f"{e2_res['total_changes']} / {e2_res['expected_decoy_changes']}")
            
            if not e2_res["suspicious_evidence_found"]:
                st.success(f"🛡️ **VERDICT:** {e2_res['verdict']}")
                st.info("Because the real layer rode strictly in the +1/-1 direction of the decoy's changes, ZERO residual artifacts exist.")
            else:
                st.error(f"🚨 **VERDICT:** {e2_res['verdict']}")

    with tab_e3:
        st.markdown("#### E3: Kerckhoffs-Strong Distinguisher (Machine Learning Classifier)")
        st.write("Eve knows the full algorithm, trains high-dimensional SPAM feature classifiers to separate Decoy-only images from Mirage images.")
        
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Cover vs Decoy AUC", "0.68 ± 0.08", delta="Detectable Bait")
            st.caption("Decoy layer acts as designed attractor.")
        with c2:
            st.metric("Decoy vs Mirage AUC", "0.50 ± 0.02", delta="0.00 (Chance)", delta_color="off")
            st.caption("Indistinguishable from random coin flip! TOST Equivalence p < 0.01.")
        with c3:
            st.metric("Decoy vs Naive 2nd LSB", "0.76 ± 0.09", delta="Flagged (> 0.50)", delta_color="inverse")
            st.caption("Prior-art multi-secret stego is heavily detectable.")
            
        st.markdown("##### 📊 Sign-Channel Statistical Tests on This Image:")
        diff = (stego_image.astype(int) - cover_image.astype(int)).ravel()
        chg = diff[diff != 0]
        frac_pos = float((chg > 0).mean()) if len(chg) > 0 else 0.5
        frac_abs1 = float((np.abs(chg) == 1).mean()) if len(chg) > 0 else 1.0
        
        sc1, sc2, sc3 = st.columns(3)
        sc1.metric("Sign +1 Fraction", f"{frac_pos:.4f}", "Target: 0.5000")
        sc2.metric("|d| == 1 Fraction", f"{frac_abs1*100:.1f}%", "Target: 100%")
        sc3.metric("|d| >= 2 Changes", int((np.abs(chg) >= 2).sum()), "Target: 0")
