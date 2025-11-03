#!/usr/bin/env ruby
#
# PCルーター (RPI) 上でDNSクエリを監視し、
# 送信元IPごと、TLD (ccTLD) ごとの問い合わせ回数を集計するスクリプト。
#
# [使い方]
# 1. このスクリプトに実行権限を与えます (chmod +x analyze_tld.rb)
# 2. sudo で実行します (sudo ./analyze_tld.rb)
#

# --- ▼ 設定 ▼ ---

# 監視対象のインターフェース
# (AP側、クライアントが接続している側を wlan1 とします)
INTERFACE = 'wlan0'

# 集計結果を表示する間隔 (秒)
PRINT_INTERVAL = 30

# --- ▲ 設定 ▲ ---


#
# ヘルパー関数: ドメイン名からTLDを抽出する
# (例: "www.google.co.jp" -> "jp")
# (例: "www.google.com" -> "com")
#
def get_tld(domain)
  # ドメイン名を '.' で分割
  parts = domain.split('.')
  
  if parts.empty?
    return "(unknown)"
  end
  
  # 最後の部分 (TLD) を小文字で返す
  # "www.google.co.jp" の場合、'jp' が返る
  # "www.google.com" の場合、'com' が返る
  return parts.last.downcase
end


#
# 集計結果を表示する関数
#
def print_stats(stats)
  puts "--- [#{Time.now}] DNSクエリTLD集計 (過去#{PRINT_INTERVAL}秒) ---"
  
  if stats.empty?
    puts " (この期間のDNSクエリはありませんでした)"
    return
  end

  # 送信元IP (statsのキー) でループ
  stats.each do |src_ip, tld_counts|
    puts "▼ 送信元IP: #{src_ip}"
    
    # TLDごとのカウント (tld_counts) を回数でソート (降順)
    sorted_tlds = tld_counts.sort_by { |_tld, count| -count }
    
    # ソートした結果を表示
    sorted_tlds.each do |tld, count|
      puts "    -> TLD: #{tld.ljust(10)} | 回数: #{count}"
    end
    puts "-" * 20
  end
  puts "--- 集計終了 ---"
  puts "" # 見やすいように空行を入れる
end

# --- メイン処理 ---
puts "DNSクエリTLD分析を開始します。(Interface: #{INTERFACE})"
puts "このスクリプトは tcpdump を使用するため、sudo で実行してください。"
puts "約 #{PRINT_INTERVAL} 秒ごとに集計結果を表示します。(Ctrl+Cで終了)"

# 集計用ハッシュ
# 以下の構造でデータを格納します
# stats[送信元IP][TLD名] = 問い合わせ回数
# (例: stats["172.16.0.237"]["jp"] = 10)
stats = Hash.new { |h, k| h[k] = Hash.new(0) }

# 最後に集計を表示した時間
last_print_time = Time.now

# tcpdump コマンド
# -i : インターフェース指定 (wlan1)
# -n : 名前解決しない (IPとポート番号で表示)
# -l : ラインバッファリング (1行ずつ即時出力)
# -t : タイムスタンプ非表示 (解析しやすくするため)
# 'port 53' : DNS (UDP/TCP 53番ポート) のみをフィルタ
tcpdump_cmd = "sudo tcpdump -i #{INTERFACE} -nl -t 'port 53'"

# tcpdump のDNSクエリ行を解析する正規表現
# グループ1: Src IP (ポート番号は除外)
# グループ2: Query Domain (末尾のドットは除外)
# (例: "IP 172.16.0.237.53723 > 8.8.8.8.53: 12345+ A? www.google.com. (32)")
REGEX = /^IP (.+?)\.\d+ > .+?: \d+\+ \w+\? (.+?)\. \(.*$/

begin
  # IO.popen で tcpdump を起動し、標準出力をパイプで受け取る
  IO.popen(tcpdump_cmd) do |io|
    
    # tcpdump の出力を1行ずつ処理
    io.each_line do |line|
      
      # --- DNSクエリ解析 ---
      # 正規表現にマッチする行 (DNSクエリの行) のみ処理
      if line.match(REGEX)
        src_ip = $1 # グループ1 (送信元IP)
        domain = $2 # グループ2 (ドメイン名)

        # ドメイン名からTLDを抽出
        tld = get_tld(domain)
        
        # 集計ハッシュのカウントを増やす
        stats[src_ip][tld] += 1
      end
      
      # --- 定期的な結果表示 ---
      current_time = Time.now
      # 前回の表示から PRINT_INTERVAL (30秒) 以上経過したかチェック
      if (current_time - last_print_time) > PRINT_INTERVAL
        
        # 集計結果を表示する
        print_stats(stats)
        
        # 集計ハッシュをクリアして、次の30秒間の集計を新しく開始
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
  # その他のエラー
  puts "\nエラーが発生しました: #{e.message}"
  puts "tcpdumpの実行に失敗したか、権限がない可能性があります。"
  puts "sudoで実行しているか確認してください。"
end

