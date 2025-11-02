#!/usr/bin/env ruby

#
# tcpdump の標準出力を監視し、DNSクエリをリアルタイムで集計するスクリプト
#
# [使い方]
# 1. 'set' ライブラリが必要 (Ruby標準)
# 2. このスクリプトに実行権限を与えます (chmod +x analyze_dns.rb)
# 3. sudo で実行します (sudo ./analyze_dns.rb)
#

require 'set' # 重複するクエリを除外するために Set を使用

# --- ▼ 設定 ▼ ---
# 監視するインターフェース (例: 'eth0', 'wlan1', 'any')
# RPIルーターのインターネット側 (WAN側) を 'eth0' と仮定
INTERFACE = 'wlan1'

# 集計結果を表示する間隔 (秒)
PRINT_INTERVAL = 30
# --- ▲ 設定 ▲ ---

# 集計結果を表示する関数
def print_stats(stats)
  puts "--- [#{Time.now}] DNSクエリ集計 (過去#{PRINT_INTERVAL}秒) ---"
  
  if stats.empty?
    puts " (この期間のDNSクエリはありませんでした)"
  end

  stats.each do |src_ip, query_set|
    puts "▼ 送信元IP: #{src_ip}"
    
    # Set に保されたユニークなドメイン名を一覧表示
    query_set.each do |domain|
      puts "    -> #{domain}"
    end
    puts "-" * 20
  end
  puts "--- 集計終了 ---"
  puts "" # 見やすいように空行を入れる
end

# --- メイン処理 ---
puts "DNSクエリ分析を開始します。(Interface: #{INTERFACE})"
puts "このスクリプトは tcpdump を使用するため、sudo で実行してください。"
puts "約 #{PRINT_INTERVAL} 秒ごとに集計結果を表示します。(Ctrl+Cで終了)"

# 集計用ハッシュ
# stats[src_ip] = <Set: {"domain1.com", "domain2.jp", ...}>
stats = Hash.new { |h, k| h[k] = Set.new }

last_print_time = Time.now

# tcpdump コマンド
# -i : インターフェース指定
# -n : 名前解決しない (IPとポート番号で表示)
# -l : ラインバッファリング (1行ずつ即時出力)
# -t : タイムスタンプ非表示 (解析しやすくするため)
# 'port 53' : DNS (UDP/TCP 53番ポート) のみをフィルタ
tcpdump_cmd = "sudo tcpdump -i #{INTERFACE} -nl -t 'port 53'"

# tcpdump のDNSクエリ行を解析する正規表現
# グループ1: Src IP (ポート番号は除外)
# グループ2: Query Domain (末尾のドットは除外)
# (例: "IP 172.16.0.120.53723 > 8.8.8.8.53: 12345+ A? www.google.com. (32)")
# (PTR? などの逆引きクエリにも対応)
REGEX = /^IP (.+?)\.\d+ > .+?: \d+\+ \w+\? (.+?)\. \(.*$/

begin
  # IO.popen で tcpdump を起動し、標準出力をパイプで受け取る
  IO.popen(tcpdump_cmd) do |io|
    io.each_line do |line|
      
      # --- DNSクエリ解析 ---
      # "A?" (IPv4), "AAAA?" (IPv6), "PTR?" (逆引き) などのクエリ行にマッチ
      if line.match(REGEX)
        src_ip = $1
        domain = $2

        # 集計 (Set に追加することで、重複するクエリは自動的に無視される)
        stats[src_ip].add(domain)
      end
      
      # --- 定期的な結果表示 ---
      current_time = Time.now
      if (current_time - last_print_time) > PRINT_INTERVAL
        print_stats(stats)
        
        # 集計リセット
        stats.clear
        last_print_time = current_time
      end

    end
  end
rescue Interrupt
  # Ctrl+C で終了したとき
  puts "\n--- 終了時の最終集計 ---"
  print_stats(stats)
  puts "分析を終了します。"
rescue => e
  puts "\nエラーが発生しました: #{e.message}"
  puts "tcpdumpの実行に失敗したか、権限がない可能性があります。"
  puts "sudoで実行しているか確認してください。"
end

