Your research focuses on the large-scale measurement and analysis of DNS over HTTPS (DoH) deployments, particularly within IPv6 networks. By conducting extensive measurements over a nine-month period in 2024, you have compiled the most comprehensive list of DoH servers to date, strictly adhering to RFC 8484 standards. Your findings reveal a significant increase in active IPv6 DoH servers, with numbers reaching 37 times greater than those discovered in studies from 2021 to 2022. However, you also identified prevalent misconfigurations among these servers, likely due to administrative oversight or the use of private servers. Notably, nearly half of the responses to DoH recursive queries originate from non-recursive servers, such as Microsoft's non-recursive referral servers. Additionally, some recursive servers, like Akamai's malfunctioning DoH recursive servers, fail to return domain resolution results. Your analysis of DoH response headers, DNS response headers, and DNS payloads highlights issues such as abnormal response headers, packet payload anomalies, and improper caching strategies. Based on these measurements, you propose potential improvements for enhancing the resolution capabilities and security of future DoH servers.
