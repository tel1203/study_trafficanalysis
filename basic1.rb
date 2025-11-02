#!/usr/bin/env ruby

#
# tcpdump の標準出力をリアルタイムで集計・分析するスクリプト
#
# [使い方]
# 1. このスクリプトに実行権限を与えます (chmod +x analyze_traffic.rb)
# 2. sudo で実行します (sudo ./analyze_traffic.rb)
#

# --- ▼ 設定 ▼ ---
# 監視するインターフェース (例: 'eth0', 'wlan1', 'any')
# RPIルーターのインターネット側を監視する場合は 'eth0'
INTERFACE = 'eth0'

# 集計結果を表示する間隔 (秒)
PRINT_INTERVAL = 60

# 表示する上位N件
TOP_N = 10
# --- ▲ 設定 ▲ ---

# IP.Port (例: 1.2.3.4.12345) から IP (例: 1.2.3.4) を抽出するヘルパー関数
def parse_ip_from_tcpdump(ip_with_port)
  # IPv4を想定 (tcpdump -n の出力 '1.2.3.4.12345' や '1.2.3.4.http' に対応)
  parts = ip_with_port.split('.')
  if parts.length > 4
    # 最後の部分 (ポート/サービス名) を除外
    return parts[0..3].join('.')
  else
    # IPアドレスのみ (ポートなし)
    return ip_with_port
  end
end

# 集計結果を表示する関数
def print_stats(stats, top_n)
  puts "--- [#{Time.now}] トラフィック集計 (上位#{top_n}件) ---"
  
  stats.each do |src_ip, dst_counts|
    puts "▼ 送信元IP: #{src_ip}"
    
    # パケット数でソート (降順)
    sorted_dsts = dst_counts.sort_by { |_dst_ip, data| -data[:packets] }
    
    sorted_dsts.first(top_n).each_with_index do |(dst_ip, data), index|
      puts "  #{index + 1}. 宛先: #{dst_ip.ljust(15)} | パケット数: #{data[:packets].to_s.rjust(6)} | バイト数: #{data[:bytes].to_s.rjust(9)}"
    end
    
    if sorted_dsts.length > top_n
      puts "  ... (他 #{sorted_dsts.length - top_n} 件の宛先)"
    end
    puts "-" * 30
  end
  puts "--- 集計終了 ---"
  puts "" # 見やすいように空行を入れる
end

# --- メイン処理 ---
puts "トラフィック分析を開始します。(Interface: #{INTERFACE})"
puts "このスクリプトは tcpdump を使用するため、sudo で実行してください。"
puts "約 #{PRINT_INTERVAL} 秒ごとに集計結果を表示します。(Ctrl+Cで終了)"

# 集計用ハッシュ
# stats[src_ip][dst_ip] = { packets: X, bytes: Y }
stats = Hash.new { |h, k| h[k] = Hash.new { |h2, k2| h2[k2] = { packets: 0, bytes: 0 } } }

last_print_time = Time.now

# tcpdump コマンド
# -i : インターフェース指定
# -n : 名前解決しない (IPとポート番号で表示)
# -l : ラインバッファリング (1行ずつ即時出力)
# -t : タイムスタンプ非表示 (解析しやすくするため)
# ip : IPパケットのみフィルタ
tcpdump_cmd = "sudo tcpdump -i #{INTERFACE} -nl -t ip"

# tcpdump 出力の解析用正規表現
# グループ1: Src IP.Port (例: 1.2.3.4.12345)
# グループ2: Dst IP.Port (例: 5.6.7.8.80)
# グループ3: Length (例: 100) (lengthがない場合は nil)
# (IPv4パケット "IP ..." のみを対象とします)
REGEX = /^IP (.+?) > (.+?):.*?(?:length (\d+))?.*$/

begin
  # IO.popen で tcpdump を起動し、標準出力をパイプで受け取る
  IO.popen(tcpdump_cmd) do |io|
    io.each_line do |line|
      
      # --- パケット解析 ---
      if line.match(REGEX)
        src_ip_port = $1
        dst_ip_port = $2
        length = $3.to_i # lengthがない (nil) 場合、to_i は 0 になる

        src_ip = parse_ip_from_tcpdump(src_ip_port)
        dst_ip = parse_ip_from_tcpdump(dst_ip_port)

        # 集計
        stats[src_ip][dst_ip][:packets] += 1
        stats[src_ip][dst_ip][:bytes] += length
      end
      
      # --- 定期的な結果表示 ---
      # (パケット受信のたびにチェックする)
      current_time = Time.now
      if (current_time - last_print_time) > PRINT_INTERVAL
        print_stats(stats, TOP_N)
        
        # 集計リセット
        stats.clear
        last_print_time = current_time
      end

    end
  end
rescue Interrupt
  # Ctrl+C で終了したとき
  puts "\n--- 終了時の最終集計 ---"
  print_stats(stats, TOP_N)
  puts "分析を終了します。"
rescue => e
  puts "\nエラーが発生しました: #{e.message}"
  puts "tcpdumpの実行に失敗したか、権限がない可能性があります。"
  puts "sudoで実行しているか確認してください。"
end

