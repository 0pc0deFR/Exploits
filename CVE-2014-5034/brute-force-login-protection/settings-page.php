<style type="text/css">
    .brute-force-login-protection .status-yes{
        color:#27ae60;
    }
    .brute-force-login-protection .status-no{
        color:#cd3d2e;
    }
    .brute-force-login-protection .postbox-footer{
        padding:10px;
        clear:both;
        border-top:1px solid #ddd;
        background:#f5f5f5;
    }
    .brute-force-login-protection input[type="number"] {
        width:60px;
    }
</style>

<script type="text/javascript">
    function ResetOptions() {
        if (confirm("<?php _e('Are you sure you want to reset all options?', 'brute-force-login-protection'); ?>")) {
            document.forms["reset_form"].submit();
        }
    }
</script>

<div class="wrap brute-force-login-protection">
    <h2><?php _e('Brute Force Login Protection Settings', 'brute-force-login-protection'); ?></h2>

    <div class="metabox-holder">
        <div class="postbox">
            <?php $status = $this->__checkRequirements(); ?>
            <h3>
                <?php _e('Status', 'brute-force-login-protection'); ?>
                <?php if (in_array(false, $status)): ?>
                    <span class="dashicons dashicons-no status-no"></span><small class="status-no"><?php _e('You are not protected!', 'brute-force-login-protection'); ?></small>
                <?php else: ?>
                    <span class="dashicons dashicons-yes status-yes"></span><small class="status-yes"><?php _e('You are protected!', 'brute-force-login-protection'); ?></small>
                <?php endif; ?>
            </h3>
            <div class="inside">
                <?php if ($status['found']): ?>
                    <span class="dashicons dashicons-yes status-yes"></span> <strong><?php _e('.htaccess file found', 'brute-force-login-protection'); ?></strong>
                <?php else: ?>
                    <span class="dashicons dashicons-no status-no"></span> <strong><?php _e('.htaccess file not found', 'brute-force-login-protection'); ?></strong>
                <?php endif; ?>
                <br />
                <?php if ($status['readable']): ?>
                    <span class="dashicons dashicons-yes status-yes"></span> <strong><?php _e('.htaccess file readable', 'brute-force-login-protection'); ?></strong>
                <?php else: ?>
                    <span class="dashicons dashicons-no status-no"></span> <strong><?php _e('.htaccess file not readable', 'brute-force-login-protection'); ?></strong>
                <?php endif; ?>
                <br />
                <?php if ($status['writeable']): ?>
                    <span class="dashicons dashicons-yes status-yes"></span> <strong><?php _e('.htaccess file writeable', 'brute-force-login-protection'); ?></strong>
                <?php else: ?>
                    <span class="dashicons dashicons-no status-no"></span> <strong><?php _e('.htaccess file not writeable', 'brute-force-login-protection'); ?></strong>
                <?php endif; ?>
            </div>
        </div>

        <div class="postbox">
            <h3><?php _e('Options', 'brute-force-login-protection'); ?></h3>
            <form method="post" action="options.php"> 
                <?php settings_fields('brute-force-login-protection'); ?>
                <div class="inside">
                    <p><strong><?php _e('Allowed login attempts before blocking IP', 'brute-force-login-protection'); ?></strong></p>
                    <p><input type="number" min="1" name="bflp_allowed_attempts" value="<?php echo $this->__options['allowed_attempts']; ?>" /></p>

                    <p><strong><?php _e('Minutes before resetting login attempts count', 'brute-force-login-protection'); ?></strong></p>
                    <p><input type="number" min="1" name="bflp_reset_time" value="<?php echo $this->__options['reset_time']; ?>" /></p>

                    <p><strong><?php _e('Inform user about remaining login attempts on login page', 'brute-force-login-protection'); ?></strong></p>
                    <p><input type="checkbox" name="bflp_inform_user" value="true" <?php echo ($this->__options['inform_user']) ? 'checked' : ''; ?> /></p>

                    <p><strong><?php _e('.htaccess file location', 'brute-force-login-protection'); ?></strong></p>
                    <p><input type="text" size="50" name="bflp_htaccess_dir" value="<?php echo $this->__options['htaccess_dir']; ?>" /></p>
                </div>
                <div class="postbox-footer">
                    <?php submit_button(__('Save', 'brute-force-login-protection'), 'primary', 'submit', false); ?>&nbsp;
                    <a href="javascript:ResetOptions()" class="button"><?php _e('Reset', 'brute-force-login-protection'); ?></a>
                </div>
            </form>
        </div>

        <div class="postbox">
            <h3><?php _e('Manually block IP', 'brute-force-login-protection'); ?></h3>
            <form method="post" action="">
                <div class="inside">
                    <p><strong><?php _e('IP address', 'brute-force-login-protection'); ?></strong></p>
                    <p><input type="text" name="IP" /></p>
                </div>
                <div class="postbox-footer">
                    <input type="submit" name="block" value="<?php echo __('Block', 'brute-force-login-protection'); ?>" class="button button-primary" />
                </div>
            </form>
        </div>
    </div>

    <h3><?php _e('Blocked IPs', 'brute-force-login-protection'); ?></h3>
    <table class="wp-list-table widefat fixed">
        <thead>
            <tr>
                <th width="5%">#</th>
                <th width="35%"><?php _e('Address', 'brute-force-login-protection'); ?></th>
                <th width="60%"><?php _e('Actions', 'brute-force-login-protection'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php
            $i = 1;
            foreach ($this->__getDeniedIPs() as $deniedIP):
                ?>
                <tr>
                    <td><?php echo $i; ?></td>
                    <td><strong><?php echo $deniedIP ?></strong></td>
                    <td>
                        <form method="post" action="">
                            <input type="hidden" name="IP" value="<?php echo $deniedIP ?>" />
                            <input type="submit" name="unblock" value="<?php echo __('Unblock', 'brute-force-login-protection'); ?>" class="button" />
                        </form>
                    </td>
                </tr>
                <?php
                $i++;
            endforeach;
            ?>
        </tbody>
    </table>

    <form id="reset_form" method="post" action="">
        <input type="hidden" name="reset" value="true" />
    </form>
</div>