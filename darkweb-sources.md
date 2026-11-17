# Candidate underground sources

This is the researcher's target list, **not a verified directory of current sites**. Names, availability, and ownership can change. No URL or credential is bundled with the repository, and none of these direct collectors is enabled by default.

| Candidate | Proposed collection route | Current state in pipeline |
| --- | --- | --- |
| XSS | Public listing via a verified v3 onion URL, if safe to use | Disabled; user flagged disruption / honeypot risk; avoid treating a claimed successor as authentic |
| Exploit.in | Public announcement listing or RSS, if available | Disabled; URL and page format needed |
| BHF | Public announcement listing or RSS, if available | Disabled; URL and page format needed |
| Dread | Public community listing, if available | Disabled; verify the replacement onion address after its October 2026 hijack |
| DarkForums | Public surface or onion listing, if available | Disabled; URL and page format needed |
| Altenen | Public surface listing, if available | Disabled; URL and page format needed |
| CryptBB | Public onion listing, if available | Disabled; URL and page format needed |
| Cracked | Public surface listing, if available | Disabled; user flagged seizure / resurfacing uncertainty |
| DamageLib | Public onion listing, if available | Disabled; URL and page format needed |
| ShinyHunters DLS | Public leak-site announcement listing, if available | Disabled as a direct source; claims may appear in Ransomware.live's active RSS feed |

## Additional niche candidates

Recent underground research suggests these more focused sources to evaluate next. They are **research candidates, not configured endpoints**; current addresses and access conditions need independent verification.

| Candidate | Research value | Proposed route |
| --- | --- | --- |
| [RehubCom](https://www.slcyber.io/learn/hacking-forums) | Russian-language XSS successor with initial-access, malware, and affiliate listings | Public announcement/category listing only, if available |
| [NotBreachForums](https://www.slcyber.io/learn/hacking-forums) | Breach-data listings and actor migration after BreachForums disruptions | Public listings only; verify ownership and avoid data downloads |
| [PwnForums](https://www.slcyber.io/learn/hacking-forums) | Another 2026 breach-forum successor; useful for tracking duplicated or disputed claims | Public listings only; compare claims against other sources |
| [Spear](https://www.slcyber.io/learn/hacking-forums) | Smaller forum focused on infostealer logs and stolen-data advertisements | Public listings only, if an authenticated address is found |
| [T1erOne](https://www.slcyber.io/learn/hacking-forums) | Ransomware affiliate recruitment after RAMP's seizure | Watch secondary reporting; the forum reportedly requires paid access, so no direct collector is planned |

Searchlight Cyber's [current forum guide](https://www.slcyber.io/learn/hacking-forums) describes these communities and reports that Dread changed onion address after an October 2026 hijack. [Flashpoint's XSS analysis](https://flashpoint.io/blog/understanding-illicit-ecosystems-xss-russian-speaking-underground/) explains why DamageLib and RehubCom are useful successors to watch and why claimed XSS revivals need careful authentication.

### Public defender forums

| Candidate | Research value | Proposed route |
| --- | --- | --- |
| [BleepingComputer Ransomware Help](https://www.bleepingcomputer.com/forums/) | Public victim-support threads can reveal new ransomware behavior and decryptor questions | Manual review first; only add a narrowly scoped public feed if one is confirmed |
| [MalwareTips Malware Analysis](https://malwaretips.com/forums/malware-analysis.140/) | Reverse engineering and sample discussion, though the forum currently has low new-thread volume | Public forum RSS, if reachable and still maintained; do not follow sample links |
| [Wilders Security malware problems & news](https://www.wilderssecurity.com/misc/quick-navigation-menu?selected=node-131) | Public malware and security issue discussions can surface user-observed campaigns | Manual review first; verify a category feed and access rules before polling |
| RAMP | Historically valuable for ransomware affiliate and initial-access activity | Archive/reference only: reporting says the forum was seized in January 2026; do not treat a replacement domain as authentic without verification |

The first three are defender communities, not underground actor forums. They can help corroborate technical behavior but do not independently verify a criminal actor's victim claim. [Rapid7's forum analysis](https://www.rapid7.com/blog/post/tr-initial-access-broker-shift-high-value-targets-premium-pricing/) supports the historical importance of RAMP and DarkForums; [RAMP seizure reporting](https://www.bleepingcomputer.com/news/security/fbi-seizes-ramp-cybercrime-forum-used-by-ransomware-gangs/) explains why it is not an active default source.

For a verified **public** v3 onion RSS feed, copy the disabled `onion_feed` source in `config.example.json`, set its URL and name, and enable it. For a public HTML listing, use `onion_html` and set `entry_tag` plus `entry_class` to the repeated post container. Each adapter fetches only the configured listing URL, through Tor, no more often than its `min_interval_minutes`. It does not sign in, run scripts, fetch linked posts, or download attachments. A site that hides all content behind login or JavaScript needs a separate, reviewed integration; this generic adapter will report no items.

Use `./bin/intel status` after enabling each source (or `.\bin\intel.exe status` on Windows). Validate that new items show the expected title, timestamp, and same-site URL before relying on the source in a brief. A claim on a criminal forum or leak site remains unverified until corroborated independently.
