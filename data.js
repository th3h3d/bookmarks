const dataSet = [
    ['#phishingAnalysis,', 'https://toolbox.googleapps.com/apps/messageheader/analyzeheader', 'Mail header analysis'],
    ['#phishingAnalysis', 'https://mha.azurewebsites.net/', 'Mail header analysis'],
    ['#phishingAnalysis', 'https://mailheader.org/', 'Mail header analysis'],
    ['#phishingAnalysis', 'https://ipinfo.io/', 'Sender IP check'],
    ['#phishingAnalysis', 'https://urlscan.io/', 'URL scanner'],
    ['#phishingAnalysis', 'https://www.url2png.com/', 'URL scanner'],
    ['#phishingAnalysis', 'https://www.wannabrowser.net/', 'URL scanner'],
    ['#phishingAnalysis', 'https://talosintelligence.com/reputation', 'URL reputation'],
    ['#phishingAnalysis', 'https://www.convertcsv.com/url-extractor.htm', 'URL extractor'],
    ['#phishingAnalysis', 'https://talosintelligence.com/reputation', 'Attachment checker & hash checker'],
    ['#phishingAnalysis', 'https://www.virustotal.com/gui/', 'Attachment checker & hash checker'],
    ['#malwareAnalysis', 'https://app.any.run/', 'Malware sandbox'],
    ['#malwareAnalysis', 'https://www.hybrid-analysis.com/', 'Malware sandbox'],
    ['#malwareAnalysis', 'https://www.joesecurity.org/#', 'Malware sandbox'],
    ['#phishingAnalysis', 'https://www.phishtool.com/', 'All in one phishing analysis tool'],
    ['#phishingAnalysis', 'https://mxtoolbox.com/', 'Email analysis tools'],
    ['#phishingAnalysis', 'https://phishtank.com/', 'Email link checker'],
    ['#phishingAnalysis', 'https://mxtoolbox.com/dmarc/details/what-is-a-dmarc-record', 'DMARC record explanation'],
    ['#phishingAnalysis', 'https://www.incidentresponse.org/playbooks/phishing', 'Phishing attack incident response playbook'],
    ['#phishingAnalysis, #wireshark', 'https://www.malware-traffic-analysis.net/2018/12/19/index.html', 'Malware traffic analysis'],
    ['#phishingAnalysis', 'https://phishcheck.me/', 'Phishing URL check'],
    ['#phishingAnalysis', 'https://checkphish.ai/', 'Phishing URL check'],
    ['#phishingAnalysis', 'https://threatcop.com/phishing-url-checker', 'Phishing URL Check'],
    ['#phishing, #malware #internet', 'https://www.arin.net/', 'Abuse Reporting'],
    ['#forensic', 'https://29a.ch/photo-forensics/#noise-analysis', 'Image forensic'],
    ['#metadata, #EXIF', 'https://29a.ch/photo-forensics/#noise-analysis', 'File Metadata reviewer'],
    ['#transfer, #file', 'https://send-anywhere.com/', 'Free file transfer'],
    ['#javascript', 'https://lelinhtinh.github.io/de4js/', 'Javascript deobfuscator'],
    ['#encryption, #encoding', 'https://gchq.github.io/CyberChef/', 'Cyberchef'],
    ['#phishingAnalysis, #file', 'https://smallpdf.com/pdf-reader', 'PDF reviewer'],
    ['#phishingAnalysis', 'https://mxtoolbox.com/public/content/emailheaders/#/ProtonMail', 'How to get email headers for all client'],
    ['#malwareAnalysis, #course', 'https://academy.tcm-sec.com/p/practical-malware-analysis-triage/?affcode=770707_llmpidil', 'Practical Malware Analysis & Triage'],
    ['#malwareAnalysis, #course', 'https://0verfl0w.podia.com/view/courses/malware-analysis-course', 'The Beginner Malware Analysis Course'],
    ['#malwareAnalysis, #course', 'https://courses.zero2auto.com/view/courses/beginner-bundle', 'Ultimate Malware Reverse Engineering Bundle'],
    ['#malwareAnalysis, #blog', 'https://cocomelonc.github.io/', 'Blog about malware analysis'],
    ['#malwareAnalysis, #blog', 'https://www.patreon.com/oalabs/posts?filters[tag]=RE101', 'Malware analysis by open analysis!'],
    ['#malwareAnalysis, #course', 'https://maldevacademy.com/', 'Malware development'],
    ['#malwareAnalysis, #course', 'https://ethicalhackersacademy.com/products/malware-analysis-training/', 'Malware analysis'],
    ['#malwareAnalysis, #course', 'https://redteamacademy.com/courses/malware-analysis-course-online/', 'Malware analysis course online'],
    ['#malwareAnalysis, #course', 'https://app.letsdefend.io/training/lessons/malware-analysis-fundamentals', 'Malware Analysis Fundamentals'],
    ['#malwareAnalysis, #course', 'https://www.mandiant.com/academy/courses/mamc', 'Malware Analysis Master Course'],
    ['#malwareAnalysis, #course, #youtube', 'https://www.youtube.com/watch?v=qA0YcYMRWyI&t=9589s', ' Malware Analysis In 5+ Hours - Full Course - Learn Practical Malware Analysis! '],
    ['#transfer, #text', 'https://justpaste.it/', 'Free online text transfer'],
    ['#phishingAnalysis, #domainSecurity', 'https://dmarcian.com/', 'DMARC Domain Checker'],
    ['#malwareAnalysis, #course, #youtube','https://www.youtube.com/watch?v=20xYpxe8mBg',' Practical Malware Analysis Essentials for Incident Responders'],
    ['#phishingAnalysis','https://qrcodescan.in/','Scan QR code'],
    ['#malwareAnalysis','https://tracker.viriback.com/','C2 seacher'],
    ['#malwareAnalysis','https://search.censys.io/','IP seacher'],
    ['#malwareAnalysis','https://threatfox.abuse.ch/browse/','C2 seacher'],
    ['#malwareAnalysis','https://cutter.re/','Open source disassembler, Free and Open Source RE Platform powered by Rizin '],
    ['#malwareAnalysis','https://rizin.re/','Free and Open Source Reverse Engineering Framework'],
    ['#malwareAnalysis','https://tria.ge/','Malware Sandbox']
    
    
    
    
    


];
 
new DataTable('#example', {
    columns: [
        { title: 'Tags' },
        { title: 'URLs/Domains' },
        { title: 'Description' },
    ],
    data: dataSet,
    lengthMenu: [ [25, 50, -1], [25, 50, "All"] ]
});
