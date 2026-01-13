/* Neon glow for live feed events + insight pulse */
const liveFeed = document.getElementById('liveFeed');
const observer = new MutationObserver(() => {
    liveFeed.querySelectorAll('.event').forEach(ev=>{
        // add neon pulse to newly inserted events
        if(!ev.classList.contains('seen')){
            ev.classList.add('seen');
            ev.style.boxShadow = '0 0 12px #34ff9b, 0 0 24px #34ff9b';
            ev.style.transform = 'translateY(-6px)';
            setTimeout(()=>{ ev.style.boxShadow = ''; ev.style.transform='translateY(0)'; }, 700);
            // brief highlight for insight and suggestion
            const ins = ev.querySelector('.insight');
            const sug = ev.querySelector('.suggestion');
            if(ins) { ins.style.opacity = '1'; ins.style.transform='translateY(0)'; }
            if(sug) { sug.style.opacity = '1'; sug.style.transform='translateY(0)'; }
        }
    });
});
observer.observe(liveFeed, { childList:true });

/* Table row highlight on update */
const attackTable = document.getElementById('attackTable');
const tableObserver = new MutationObserver(() => {
    attackTable.querySelectorAll('tr').forEach(tr=>{
        tr.style.transition = 'background 0.5s, transform 0.3s';
        tr.style.transform = 'scale(1.02)';
        setTimeout(()=>{ tr.style.transform='scale(1)'; },300);
    });
});
tableObserver.observe(attackTable, { childList:true });

/* Optional: click on table row to show insight (simple UX) */
attackTable.addEventListener('click', (e) => {
    const tr = e.target.closest('tr');
    if(!tr) return;
    const ins = tr.dataset.insight || 'No insight stored.';
    alert('Insight for this row:\n\n' + ins);
});
